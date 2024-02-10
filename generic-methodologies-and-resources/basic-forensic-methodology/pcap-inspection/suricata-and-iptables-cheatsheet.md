# Suricata & Iptables hile yaprağı

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> ile sıfırdan kahraman olmak için AWS hackleme öğrenin<strong>!</strong></summary>

* Bir **cybersecurity şirketinde** çalışıyor musunuz? **Şirketinizi HackTricks'te reklamını görmek** ister misiniz? veya **PEASS'ın en son sürümüne veya HackTricks'i PDF olarak indirmek** ister misiniz? [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family), özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonunu keşfedin
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) alın
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter**'da takip edin 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Hacking hilelerinizi [hacktricks repo](https://github.com/carlospolop/hacktricks) ve [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)'ya PR göndererek paylaşın**.

</details>

## Iptables

### Zincirler

Iptables'ta, zincir olarak bilinen kurallar listeleri sıralı olarak işlenir. Bunlar arasında, üç temel zincir evrensel olarak bulunur ve NAT gibi ek zincirler, sistem yeteneklerine bağlı olarak desteklenebilir.

- **Giriş Zinciri**: Gelen bağlantıların davranışını yönetmek için kullanılır.
- **İleri Zinciri**: Yerel sistem için hedeflenmeyen gelen bağlantıları yönetmek için kullanılır. Bu, yönlendirici olarak hareket eden cihazlar için tipiktir, burada alınan veriler başka bir hedefe iletilmek üzere yönlendirilmelidir. Bu zincir, sistem yönlendirme, NAT veya benzeri faaliyetlerle ilgili olduğunda öncelikli olarak ilgilidir.
- **Çıkış Zinciri**: Çıkış bağlantılarının düzenlenmesine adanmıştır.

Bu zincirler, ağ trafiğinin düzenli işlenmesini sağlar ve bir sisteme giren, içinden geçen ve çıkan veri akışını ayrıntılı kuralların belirlenmesine olanak tanır.
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

### Kurulum ve Yapılandırma

```bash
# Suricata'yı yüklemek için aşağıdaki komutu kullanın:
sudo apt-get install suricata

# Suricata'nın yapılandırma dosyasını düzenlemek için aşağıdaki komutu kullanın:
sudo nano /etc/suricata/suricata.yaml

# Suricata'nın çalışmasını sağlamak için aşağıdaki komutu kullanın:
sudo suricata -c /etc/suricata/suricata.yaml -i eth0

# Suricata'nın sistem başlangıcında otomatik olarak çalışmasını sağlamak için aşağıdaki komutu kullanın:
sudo systemctl enable suricata

# Suricata'nın çalıştığı arayüzleri kontrol etmek için aşağıdaki komutu kullanın:
sudo suricata --list-interfaces
```

### Kurallar

```bash
# Suricata kurallarını güncellemek için aşağıdaki komutu kullanın:
sudo suricata-update

# Suricata kurallarını kontrol etmek için aşağıdaki komutu kullanın:
sudo suricata-update list-enabled-rulesets

# Suricata kurallarını etkinleştirmek veya devre dışı bırakmak için aşağıdaki komutu kullanın:
sudo suricata-update enable-rule <rule-id>
sudo suricata-update disable-rule <rule-id>
```

### Loglar

```bash
# Suricata loglarını kontrol etmek için aşağıdaki komutu kullanın:
sudo tail -f /var/log/suricata/fast.log
sudo tail -f /var/log/suricata/stats.log
```

## IPTables

### Kurallar

```bash
# IPTables kurallarını listelemek için aşağıdaki komutu kullanın:
sudo iptables -L

# IPTables kurallarını temizlemek için aşağıdaki komutu kullanın:
sudo iptables -F

# IPTables kurallarını kaydetmek için aşağıdaki komutu kullanın:
sudo iptables-save > iptables-rules.txt

# IPTables kurallarını yüklemek için aşağıdaki komutu kullanın:
sudo iptables-restore < iptables-rules.txt

# IPTables kurallarını geçici olarak devre dışı bırakmak için aşağıdaki komutu kullanın:
sudo iptables -P INPUT ACCEPT
sudo iptables -P OUTPUT ACCEPT
sudo iptables -P FORWARD ACCEPT
```

### NAT

```bash
# IPTables NAT kurallarını etkinleştirmek için aşağıdaki komutu kullanın:
sudo sysctl -w net.ipv4.ip_forward=1

# IPTables NAT kurallarını eklemek için aşağıdaki komutu kullanın:
sudo iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
```
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
### Kural Tanımları

[Dökümantasyondan:](https://github.com/OISF/suricata/blob/master/doc/userguide/rules/intro.rst) Bir kural/imza aşağıdakilerden oluşur:

* **Eylem**, imza eşleştiğinde ne olduğunu belirler.
* **Başlık**, kuralın protokolünü, IP adreslerini, portları ve yönünü tanımlar.
* **Kural seçenekleri**, kuralın ayrıntılarını belirler.
```bash
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP GET Request Containing Rule in URI"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"rule"; fast_pattern; classtype:bad-unknown; sid:123; rev:1;)
```
#### **Geçerli eylemler şunlardır**

* alert - bir uyarı oluştur
* pass - paketin daha fazla denetimini durdur
* **drop** - paketi düşür ve uyarı oluştur
* **reject** - eşleşen paketin gönderene RST/ICMP ulaşılamaz hata gönder
* rejectsrc - sadece _reject_ ile aynı
* rejectdst - eşleşen paketin alıcıya RST/ICMP hata paketi gönder
* rejectboth - konuşmanın her iki tarafına da RST/ICMP hata paketi gönder

#### **Protokoller**

* tcp (tcp trafiği için)
* udp
* icmp
* ip (ip 'tümü' veya 'herhangi biri' anlamına gelir)
* _katman 7 protokolleri_: http, ftp, tls, smb, dns, ssh... (daha fazlası için [**dokümantasyon**](https://suricata.readthedocs.io/en/suricata-6.0.0/rules/intro.html))

#### Kaynak ve Hedef Adresler

IP aralıklarını, inkarları ve adres listelerini destekler:

| Örnek                          | Anlam                                    |
| ------------------------------ | ---------------------------------------- |
| ! 1.1.1.1                      | 1.1.1.1 dışındaki her IP adresi           |
| !\[1.1.1.1, 1.1.1.2]           | 1.1.1.1 ve 1.1.1.2 dışındaki her IP adresi |
| $HOME\_NET                     | yaml'daki HOME\_NET ayarınız              |
| \[$EXTERNAL\_NET, !$HOME\_NET] | EXTERNAL\_NET ve HOME\_NET dışındaki adresler |
| \[10.0.0.0/24, !10.0.0.5]      | 10.0.0.0/24, 10.0.0.5 hariç               |

#### Kaynak ve Hedef Portlar

Port aralıklarını, inkarları ve port listelerini destekler

| Örnek         | Anlam                                |
| --------------- | -------------------------------------- |
| any             | herhangi bir adres                            |
| \[80, 81, 82]   | port 80, 81 ve 82                     |
| \[80: 82]       | 80'den 82'ye kadar olan aralık                  |
| \[1024: ]       | 1024'ten en yüksek port numarasına kadar |
| !80             | 80 hariç her port                      |
| \[80:100,!99]   | 80'den 100'e kadar olan aralık, ancak 99 hariç |
| \[1:80,!\[2,4]] | 1-80 aralığı, 2 ve 4 portları hariç  |

#### Yön

Uygulanan iletişim kuralının yönünü belirtmek mümkündür:
```
source -> destination
source <> destination  (both directions)
```
#### Anahtar Kelimeler

Suricata'da **yüzlerce seçenek** bulunmaktadır ve aradığınız **belirli paketi** bulmak için kullanılabilir. Eğer ilginç bir şey bulunursa burada belirtilecektir. Daha fazlası için [**belgelendirmeye**](https://suricata.readthedocs.io/en/suricata-6.0.0/rules/index.html) göz atın!
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
<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman seviyesine öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

* Bir **cybersecurity şirketinde çalışıyor musunuz**? **Şirketinizi HackTricks'te reklamını görmek** ister misiniz? veya **PEASS'ın en son sürümüne veya HackTricks'i PDF olarak indirmek** ister misiniz? [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family), özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonunu keşfedin.
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin.
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter**'da beni takip edin 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Hacking hilelerinizi [hacktricks repo'ya](https://github.com/carlospolop/hacktricks) ve [hacktricks-cloud repo'ya](https://github.com/carlospolop/hacktricks-cloud) PR göndererek paylaşın**.

</details>
