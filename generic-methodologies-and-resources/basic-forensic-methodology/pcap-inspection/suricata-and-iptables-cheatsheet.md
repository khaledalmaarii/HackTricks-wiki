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

### Chains

В iptables списки правил, відомі як ланцюги, обробляються послідовно. Серед них три основні ланцюги завжди присутні, з додатковими, такими як NAT, які можуть підтримуватися в залежності від можливостей системи.

- **Input Chain**: Використовується для управління поведінкою вхідних з'єднань.
- **Forward Chain**: Використовується для обробки вхідних з'єднань, які не призначені для локальної системи. Це типово для пристроїв, що діють як маршрутизатори, де отримані дані призначені для пересилання в інше місце. Цей ланцюг є актуальним переважно тоді, коли система бере участь у маршрутизації, NAT або подібних діяльностях.
- **Output Chain**: Призначений для регулювання вихідних з'єднань.

Ці ланцюги забезпечують впорядковану обробку мережевого трафіку, дозволяючи визначати детальні правила, що регулюють потік даних у систему, через неї та з неї.
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
### Правила Визначення

[З документації:](https://github.com/OISF/suricata/blob/master/doc/userguide/rules/intro.rst) Правило/підпис складається з наступного:

* **дія**, визначає, що відбувається, коли підпис збігається.
* **заголовок**, визначає протокол, IP-адреси, порти та напрямок правила.
* **опції правила**, визначають специфіку правила.
```bash
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP GET Request Containing Rule in URI"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"rule"; fast_pattern; classtype:bad-unknown; sid:123; rev:1;)
```
#### **Дійсні дії**

* alert - згенерувати сповіщення
* pass - зупинити подальшу перевірку пакета
* **drop** - скинути пакет і згенерувати сповіщення
* **reject** - надіслати RST/ICMP помилку недоступності відправнику відповідного пакета.
* rejectsrc - те ж саме, що й _reject_
* rejectdst - надіслати RST/ICMP помилку пакета отримувачу відповідного пакета.
* rejectboth - надіслати RST/ICMP помилки пакетів обом сторонам розмови.

#### **Протоколи**

* tcp (для tcp-трафіку)
* udp
* icmp
* ip (ip означає «всі» або «будь-які»)
* _протоколи рівня 7_: http, ftp, tls, smb, dns, ssh... (більше в [**документації**](https://suricata.readthedocs.io/en/suricata-6.0.0/rules/intro.html))

#### Джерела та адреси призначення

Підтримує діапазони IP, заперечення та список адрес:

| Приклад                        | Значення                                  |
| ------------------------------ | ---------------------------------------- |
| ! 1.1.1.1                      | Кожна IP-адреса, крім 1.1.1.1             |
| !\[1.1.1.1, 1.1.1.2]           | Кожна IP-адреса, крім 1.1.1.1 та 1.1.1.2 |
| $HOME\_NET                     | Ваше налаштування HOME\_NET у yaml        |
| \[$EXTERNAL\_NET, !$HOME\_NET] | EXTERNAL\_NET і не HOME\_NET              |
| \[10.0.0.0/24, !10.0.0.5]      | 10.0.0.0/24, крім 10.0.0.5                |

#### Порти джерела та призначення

Підтримує діапазони портів, заперечення та списки портів

| Приклад         | Значення                                |
| --------------- | -------------------------------------- |
| any             | будь-яка адреса                        |
| \[80, 81, 82]   | порт 80, 81 і 82                       |
| \[80: 82]       | Діапазон від 80 до 82                  |
| \[1024: ]       | Від 1024 до найвищого номера порту     |
| !80             | Кожен порт, крім 80                    |
| \[80:100,!99]   | Діапазон від 80 до 100, але 99 виключено |
| \[1:80,!\[2,4]] | Діапазон від 1 до 80, крім портів 2 і 4  |

#### Напрямок

Можна вказати напрямок правила комунікації, що застосовується:
```
source -> destination
source <> destination  (both directions)
```
#### Keywords

Є **сотні варіантів** доступних у Suricata для пошуку **конкретного пакету**, який ви шукаєте, тут буде зазначено, якщо знайдено щось цікаве. Перевірте [**документацію**](https://suricata.readthedocs.io/en/suricata-6.0.0/rules/index.html) для отримання додаткової інформації!
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
Вивчайте та практикуйте AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Вивчайте та практикуйте GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Підтримайте HackTricks</summary>

* Перевірте [**плани підписки**](https://github.com/sponsors/carlospolop)!
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи Telegram**](https://t.me/peass) або **слідкуйте** за нами в **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Діліться хакерськими трюками, надсилаючи PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) та [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) репозиторіїв на github.

</details>
{% endhint %}
