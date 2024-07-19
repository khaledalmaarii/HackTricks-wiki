# Suricata & Iptables cheatsheet

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Iptables

### Zincirler

Iptables'ta, kuralların listeleri zincirler olarak adlandırılır ve sıralı bir şekilde işlenir. Bunlar arasında, evrensel olarak mevcut olan üç ana zincir bulunur; sistemin yeteneklerine bağlı olarak NAT gibi ek zincirler de desteklenebilir.

- **Giriş Zinciri**: Gelen bağlantıların davranışını yönetmek için kullanılır.
- **İleri Zincir**: Yerel sisteme yönlendirilmeyen gelen bağlantıları işlemek için kullanılır. Bu, verilerin başka bir hedefe iletilmesi gereken yönlendirici olarak işlev gören cihazlar için tipiktir. Bu zincir, sistemin yönlendirme, NAT yapma veya benzeri faaliyetlerde bulunduğu durumlarda önemlidir.
- **Çıkış Zinciri**: Giden bağlantıların düzenlenmesine adanmıştır.

Bu zincirler, ağ trafiğinin düzenli bir şekilde işlenmesini sağlar ve bir sistemin içine, içinden ve dışına veri akışını yöneten ayrıntılı kuralların belirtilmesine olanak tanır.
```bash
# Delete all rules
iptables -F

# List all rules
iptables -L
iptables -S

# Block IP addresses & ports
iptables -I INPUT -s ip1,ip2,ip3 -j DROP
iptables -I INPUT -p tcp --dport 443 -j DROP
iptables -I INPUT -s ip1,ip2 -p tcp --dport 443 -j DROP

# String based drop
## Strings are case sensitive (pretty easy to bypass if you want to check an SQLi for example)
iptables -I INPUT -p tcp --dport <port_listening> -m string --algo bm --string '<payload>' -j DROP
iptables -I OUTPUT -p tcp --sport <port_listening> -m string --algo bm --string 'CTF{' -j DROP
## You can also check for the hex, base64 and double base64 of the expected CTF flag chars

# Drop every input port except some
iptables -P INPUT DROP # Default to drop
iptables -I INPUT -p tcp --dport 8000 -j ACCEPT
iptables -I INPUT -p tcp --dport 443 -j ACCEPT


# Persist Iptables
## Debian/Ubuntu:
apt-get install iptables-persistent
iptables-save > /etc/iptables/rules.v4
ip6tables-save > /etc/iptables/rules.v6
iptables-restore < /etc/iptables/rules.v4
##RHEL/CentOS:
iptables-save > /etc/sysconfig/iptables
ip6tables-save > /etc/sysconfig/ip6tables
iptables-restore < /etc/sysconfig/iptables
```
## Suricata

### Kurulum ve Konfigürasyon
```bash
# Install details from: https://suricata.readthedocs.io/en/suricata-6.0.0/install.html#install-binary-packages
# Ubuntu
add-apt-repository ppa:oisf/suricata-stable
apt-get update
apt-get install suricata

# Debian
echo "deb http://http.debian.net/debian buster-backports main" > \
/etc/apt/sources.list.d/backports.list
apt-get update
apt-get install suricata -t buster-backports

# CentOS
yum install epel-release
yum install suricata

# Get rules
suricata-update
suricata-update list-sources #List sources of the rules
suricata-update enable-source et/open #Add et/open rulesets
suricata-update
## To use the dowloaded rules update the following line in /etc/suricata/suricata.yaml
default-rule-path: /var/lib/suricata/rules
rule-files:
- suricata.rules

# Run
## Add rules in /etc/suricata/rules/suricata.rules
systemctl suricata start
suricata -c /etc/suricata/suricata.yaml -i eth0


# Reload rules
suricatasc -c ruleset-reload-nonblocking
## or set the follogin in /etc/suricata/suricata.yaml
detect-engine:
- rule-reload: true

# Validate suricata config
suricata -T -c /etc/suricata/suricata.yaml -v

# Configure suricata as IPs
## Config drop to generate alerts
## Search for the following lines in /etc/suricata/suricata.yaml and remove comments:
- drop:
alerts: yes
flows: all

## Forward all packages to the queue where suricata can act as IPS
iptables -I INPUT -j NFQUEUE
iptables -I OUTPUT -j NFQUEUE

## Start suricata in IPS mode
suricata -c /etc/suricata/suricata.yaml  -q 0
### or modify the service config file as:
systemctl edit suricata.service

[Service]
ExecStart=
ExecStart=/usr/bin/suricata -c /etc/suricata/suricata.yaml --pidfile /run/suricata.pid -q 0 -vvv
Type=simple

systemctl daemon-reload
```
### Kurallar Tanımları

[Belgelerden:](https://github.com/OISF/suricata/blob/master/doc/userguide/rules/intro.rst) Bir kural/imza aşağıdakilerden oluşur:

* **hareket**, imza eşleştiğinde ne olacağını belirler.
* **başlık**, kuralın protokolünü, IP adreslerini, portları ve yönünü tanımlar.
* **kural seçenekleri**, kuralın ayrıntılarını tanımlar.
```bash
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP GET Request Containing Rule in URI"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"rule"; fast_pattern; classtype:bad-unknown; sid:123; rev:1;)
```
#### **Geçerli eylemler şunlardır**

* alert - bir uyarı oluştur
* pass - paketin daha fazla incelenmesini durdur
* **drop** - paketi düşür ve uyarı oluştur
* **reject** - eşleşen paketin göndericisine RST/ICMP ulaşılamaz hatası gönder
* rejectsrc - sadece _reject_ ile aynı
* rejectdst - eşleşen paketin alıcısına RST/ICMP hata paketi gönder
* rejectboth - konuşmanın her iki tarafına RST/ICMP hata paketleri gönder

#### **Protokoller**

* tcp (tcp-trafik için)
* udp
* icmp
* ip (ip 'tümü' veya 'herhangi' anlamına gelir)
* _layer7 protokolleri_: http, ftp, tls, smb, dns, ssh... (daha fazlası için [**docs**](https://suricata.readthedocs.io/en/suricata-6.0.0/rules/intro.html))

#### Kaynak ve Hedef Adresleri

IP aralıklarını, olumsuzlamaları ve adres listelerini destekler:

| Örnek                          | Anlamı                                   |
| ------------------------------ | ---------------------------------------- |
| ! 1.1.1.1                      | 1.1.1.1 hariç her IP adresi             |
| !\[1.1.1.1, 1.1.1.2]           | 1.1.1.1 ve 1.1.1.2 hariç her IP adresi  |
| $HOME\_NET                     | yaml'daki HOME\_NET ayarınız           |
| \[$EXTERNAL\_NET, !$HOME\_NET] | EXTERNAL\_NET ve HOME\_NET hariç       |
| \[10.0.0.0/24, !10.0.0.5]      | 10.0.0.0/24, 10.0.0.5 hariç            |

#### Kaynak ve Hedef Portları

Port aralıklarını, olumsuzlamaları ve port listelerini destekler

| Örnek           | Anlamı                                 |
| --------------- | -------------------------------------- |
| any             | herhangi bir adres                     |
| \[80, 81, 82]   | port 80, 81 ve 82                     |
| \[80: 82]       | 80'den 82'ye kadar aralık             |
| \[1024: ]       | 1024'ten en yüksek port numarasına kadar |
| !80             | 80 hariç her port                     |
| \[80:100,!99]   | 80'den 100'e kadar aralık ama 99 hariç |
| \[1:80,!\[2,4]] | 1-80 aralığı, port 2 ve 4 hariç       |

#### Yön

Uygulanan iletişim kuralının yönünü belirtmek mümkündür:
```
source -> destination
source <> destination  (both directions)
```
#### Anahtar Kelimeler

Suricata'da aradığınız **belirli paketi** bulmak için **yüzlerce seçenek** mevcuttur, burada ilginç bir şey bulunursa belirtilir. Daha fazla bilgi için [**belgelere**](https://suricata.readthedocs.io/en/suricata-6.0.0/rules/index.html) göz atın!
```bash
# Meta Keywords
msg: "description"; #Set a description to the rule
sid:123 #Set a unique ID to the rule
rev:1 #Rule revision number
config classification: not-suspicious,Not Suspicious Traffic,3 #Classify
reference: url, www.info.com #Reference
priority:1; #Set a priority
metadata: key value, key value; #Extra metadata

# Filter by geolocation
geoip: src,RU;

# ICMP type & Code
itype:<10;
icode:0

# Filter by string
content: "something"
content: |61 61 61| #Hex: AAA
content: "http|3A|//" #Mix string and hex
content: "abc"; nocase; #Case insensitive
reject tcp any any -> any any (msg: "php-rce"; content: "eval"; nocase; metadata: tag php-rce; sid:101; rev: 1;)

# Replaces string
## Content and replace string must have the same length
content:"abc"; replace: "def"
alert tcp any any -> any any (msg: "flag replace"; content: "CTF{a6st"; replace: "CTF{u798"; nocase; sid:100; rev: 1;)
## The replace works in both input and output packets
## But it only modifies the first match

# Filter by regex
pcre:"/<regex>/opts"
pcre:"/NICK .*USA.*[0-9]{3,}/i"
drop tcp any any -> any any (msg:"regex"; pcre:"/CTF\{[\w]{3}/i"; sid:10001;)

# Other examples
## Drop by port
drop tcp any any -> any 8000 (msg:"8000 port"; sid:1000;)
```
{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'i takip edin.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}
