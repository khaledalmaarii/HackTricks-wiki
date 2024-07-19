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

iptables에서 규칙 목록은 체인으로 알려져 있으며 순차적으로 처리됩니다. 이 중 세 가지 주요 체인은 보편적으로 존재하며, 시스템의 기능에 따라 NAT와 같은 추가 체인이 지원될 수 있습니다.

- **Input Chain**: 들어오는 연결의 동작을 관리하는 데 사용됩니다.
- **Forward Chain**: 로컬 시스템을 대상으로 하지 않는 들어오는 연결을 처리하는 데 사용됩니다. 이는 라우터 역할을 하는 장치에서 일반적이며, 수신된 데이터는 다른 목적지로 전달되도록 되어 있습니다. 이 체인은 시스템이 라우팅, NAT 또는 유사한 활동에 관여할 때 주로 관련이 있습니다.
- **Output Chain**: 나가는 연결의 규제를 전담합니다.

이 체인들은 네트워크 트래픽의 질서 있는 처리를 보장하며, 시스템으로 들어오고, 통과하고, 나가는 데이터 흐름을 규제하는 상세한 규칙을 지정할 수 있게 합니다.
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

### 설치 및 구성
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
### 규칙 정의

[문서에서:](https://github.com/OISF/suricata/blob/master/doc/userguide/rules/intro.rst) 규칙/서명은 다음으로 구성됩니다:

* **작업**: 서명이 일치할 때 발생하는 일을 결정합니다.
* **헤더**: 규칙의 프로토콜, IP 주소, 포트 및 방향을 정의합니다.
* **규칙 옵션**: 규칙의 세부 사항을 정의합니다.
```bash
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP GET Request Containing Rule in URI"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"rule"; fast_pattern; classtype:bad-unknown; sid:123; rev:1;)
```
#### **유효한 작업은**

* alert - 경고 생성
* pass - 패킷의 추가 검사를 중지
* **drop** - 패킷을 드롭하고 경고 생성
* **reject** - 일치하는 패킷의 발신자에게 RST/ICMP 도달 불가 오류 전송
* rejectsrc - 단순히 _reject_와 동일
* rejectdst - 일치하는 패킷의 수신자에게 RST/ICMP 오류 패킷 전송
* rejectboth - 대화의 양쪽에 RST/ICMP 오류 패킷 전송

#### **프로토콜**

* tcp (tcp 트래픽용)
* udp
* icmp
* ip (ip는 ‘모든’ 또는 ‘어떤’ 의미)
* _layer7 프로토콜_: http, ftp, tls, smb, dns, ssh... (자세한 내용은 [**docs**](https://suricata.readthedocs.io/en/suricata-6.0.0/rules/intro.html)에서 확인)

#### 출발지 및 목적지 주소

IP 범위, 부정 및 주소 목록을 지원합니다:

| 예시                          | 의미                                    |
| ------------------------------ | ---------------------------------------- |
| ! 1.1.1.1                      | 1.1.1.1을 제외한 모든 IP 주소          |
| !\[1.1.1.1, 1.1.1.2]           | 1.1.1.1과 1.1.1.2를 제외한 모든 IP 주소 |
| $HOME\_NET                     | yaml에서 설정한 HOME\_NET              |
| \[$EXTERNAL\_NET, !$HOME\_NET] | EXTERNAL\_NET 및 HOME\_NET 제외        |
| \[10.0.0.0/24, !10.0.0.5]      | 10.0.0.0/24에서 10.0.0.5 제외          |

#### 출발지 및 목적지 포트

포트 범위, 부정 및 포트 목록을 지원합니다.

| 예시             | 의미                                  |
| ---------------- | -------------------------------------- |
| any              | 모든 주소                              |
| \[80, 81, 82]    | 포트 80, 81 및 82                      |
| \[80: 82]        | 80부터 82까지의 범위                  |
| \[1024: ]        | 1024부터 가장 높은 포트 번호까지     |
| !80              | 80을 제외한 모든 포트                 |
| \[80:100,!99]    | 80부터 100까지의 범위에서 99 제외     |
| \[1:80,!\[2,4]] | 1-80 범위에서 포트 2와 4 제외        |

#### 방향

적용되는 통신 규칙의 방향을 나타낼 수 있습니다:
```
source -> destination
source <> destination  (both directions)
```
#### Keywords

Suricata에는 찾고 있는 **특정 패킷**을 검색하기 위한 **수백 가지 옵션**이 있습니다. 흥미로운 것이 발견되면 여기에서 언급됩니다. 더 많은 정보는 [**문서**](https://suricata.readthedocs.io/en/suricata-6.0.0/rules/index.html)를 확인하세요!
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
AWS 해킹 배우기 및 연습하기:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 배우기 및 연습하기: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원하기</summary>

* [**구독 계획**](https://github.com/sponsors/carlospolop) 확인하기!
* **💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 참여하거나 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우하세요.**
* **[**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) 깃허브 리포지토리에 PR을 제출하여 해킹 트릭을 공유하세요.**

</details>
{% endhint %}
