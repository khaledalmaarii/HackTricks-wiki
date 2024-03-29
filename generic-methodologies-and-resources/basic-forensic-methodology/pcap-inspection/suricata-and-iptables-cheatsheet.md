# Шпаргалка Suricata & Iptables

<details>

<summary><strong>Вивчайте хакінг AWS від нуля до героя з</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Ви працюєте в **кібербезпеці компанії**? Хочете побачити вашу **компанію рекламовану на HackTricks**? або хочете мати доступ до **останньої версії PEASS або завантажити HackTricks у PDF**? Перевірте [**ПЛАНИ ПІДПИСКИ**](https://github.com/sponsors/carlospolop)!
* Відкрийте для себе [**Сім'ю PEASS**](https://opensea.io/collection/the-peass-family), нашу колекцію ексклюзивних [**NFT**](https://opensea.io/collection/the-peass-family)
* Отримайте [**офіційний PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Приєднуйтесь до** [**💬**](https://emojipedia.org/speech-balloon/) [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи Telegram**](https://t.me/peass) або **слідкуйте** за мною на **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Поділіться своїми хакерськими трюками, надсилайте PR до [репозиторію hacktricks](https://github.com/carlospolop/hacktricks) та [репозиторію hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Iptables

### Ланцюги

У iptables списки правил, відомі як ланцюги, обробляються послідовно. З них три основні ланцюги універсально присутні, з можливістю підтримки додаткових, наприклад NAT, в залежності від можливостей системи.

- **Ланцюг введення (Input Chain)**: Використовується для управління поведінкою вхідних підключень.
- **Ланцюг пересилання (Forward Chain)**: Використовується для обробки вхідних підключень, які не призначені для локальної системи. Це типово для пристроїв, що діють як маршрутизатори, де отримані дані призначені для пересилання на інший призначення. Цей ланцюг є актуальним в основному тоді, коли система займається маршрутизацією, NAT або подібними діями.
- **Ланцюг виведення (Output Chain)**: Присвячений регулюванню вихідних підключень.

Ці ланцюги забезпечують порядкову обробку мережевого трафіку, дозволяючи вказати детальні правила, що регулюють потік даних в систему, через систему та з системи.
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

### Встановлення та налаштування
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
### Визначення правил

[З документації:](https://github.com/OISF/suricata/blob/master/doc/userguide/rules/intro.rst) Правило/підпис складається з наступного:

* **Дія**, визначає, що відбувається, коли підпис відповідає.
* **Заголовок**, визначає протокол, IP-адреси, порти та напрямок правила.
* **Параметри правила**, визначають конкретику правила.
```bash
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP GET Request Containing Rule in URI"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"rule"; fast_pattern; classtype:bad-unknown; sid:123; rev:1;)
```
#### **Дійсні дії**

* alert - генерувати сповіщення
* pass - зупинити подальшу перевірку пакета
* **drop** - відкинути пакет і згенерувати сповіщення
* **reject** - надіслати RST/ICMP недосяжну помилку відправнику відповідного пакета.
* rejectsrc - те саме, що просто _reject_
* rejectdst - надіслати пакет з помилкою RST/ICMP отримувачеві відповідного пакета.
* rejectboth - надіслати пакети з помилкою RST/ICMP обом сторонам розмови.

#### **Протоколи**

* tcp (для tcp-трафіку)
* udp
* icmp
* ip (ip означає "все" або "будь-яке")
* _протоколи 7-го рівня_: http, ftp, tls, smb, dns, ssh... (більше в [**документації**](https://suricata.readthedocs.io/en/suricata-6.0.0/rules/intro.html))

#### Адреси джерела та призначення

Підтримує діапазони IP-адрес, заперечення та список адрес:

| Приклад                        | Значення                                  |
| ------------------------------ | ---------------------------------------- |
| ! 1.1.1.1                      | Кожна IP-адреса, крім 1.1.1.1             |
| !\[1.1.1.1, 1.1.1.2]           | Кожна IP-адреса, крім 1.1.1.1 та 1.1.1.2 |
| $HOME\_NET                     | Ваше налаштування HOME\_NET у yaml        |
| \[$EXTERNAL\_NET, !$HOME\_NET] | EXTERNAL\_NET та не HOME\_NET          |
| \[10.0.0.0/24, !10.0.0.5]      | 10.0.0.0/24 за винятком 10.0.0.5          |

#### Порти джерела та призначення

Підтримує діапазони портів, заперечення та списки портів

| Приклад         | Значення                                |
| --------------- | -------------------------------------- |
| any             | будь-яка адреса                            |
| \[80, 81, 82]   | порт 80, 81 та 82                     |
| \[80: 82]       | Діапазон від 80 до 82                  |
| \[1024: ]       | Від 1024 до найвищого номера порту |
| !80             | Кожен порт, крім 80                      |
| \[80:100,!99]   | Діапазон від 80 до 100, але 99 виключено |
| \[1:80,!\[2,4]] | Діапазон від 1 до 80, крім портів 2 та 4  |

#### Напрямок

Можливо вказати напрямок застосованого правила комунікації:
```
source -> destination
source <> destination  (both directions)
```
#### Ключові слова

Є **сотні опцій**, доступних в Suricata для пошуку **конкретного пакету**, який ви шукаєте, тут буде зазначено, якщо щось цікаве буде знайдено. Перевірте [**документацію**](https://suricata.readthedocs.io/en/suricata-6.0.0/rules/index.html) для отримання більше інформації!
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

<summary><strong>Вивчайте хакінг AWS від нуля до героя з</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Чи працюєте ви в **кібербезпеці компанії**? Хочете побачити вашу **компанію рекламовану на HackTricks**? або хочете мати доступ до **останньої версії PEASS або завантажити HackTricks у PDF**? Перевірте [**ПЛАНИ ПІДПИСКИ**](https://github.com/sponsors/carlospolop)!
* Відкрийте [**Сім'ю PEASS**](https://opensea.io/collection/the-peass-family), нашу колекцію ексклюзивних [**NFT**](https://opensea.io/collection/the-peass-family)
* Отримайте [**офіційний PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Приєднуйтесь до** [**💬**](https://emojipedia.org/speech-balloon/) [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи Telegram**](https://t.me/peass) або **слідкуйте** за мною на **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Поділіться своїми хакерськими трюками, надсилайте PR до [репозиторію hacktricks](https://github.com/carlospolop/hacktricks) та [репозиторію hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
