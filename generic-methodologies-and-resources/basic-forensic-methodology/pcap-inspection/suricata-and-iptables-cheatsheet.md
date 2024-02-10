# Suricata & Iptables 치트시트

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

* **사이버 보안 회사**에서 일하시나요? **회사를 HackTricks에서 광고하거나 PEASS의 최신 버전에 액세스하거나 HackTricks를 PDF로 다운로드**하고 싶으신가요? [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인해보세요!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견해보세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter**에서 저를 **팔로우**하세요 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **[hacktricks repo](https://github.com/carlospolop/hacktricks)와 [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**에 PR을 제출하여 여러분의 해킹 기법을 공유해주세요.

</details>

## Iptables

### Chains

Iptables에서는 체인이라고 하는 규칙 목록이 순차적으로 처리됩니다. 이 중에서 세 가지 주요 체인이 모든 시스템에서 일반적으로 존재하며, NAT와 같은 추가 체인은 시스템의 기능에 따라 지원될 수 있습니다.

- **Input Chain**: 들어오는 연결의 동작을 관리하는 데 사용됩니다.
- **Forward Chain**: 로컬 시스템으로 가지 않는 들어오는 연결을 처리하는 데 사용됩니다. 이는 라우터로 작동하는 장치에서 일반적으로 발생하며, 받은 데이터를 다른 대상으로 전달해야 하는 경우에 해당합니다. 이 체인은 주로 시스템이 라우팅, NAT 또는 유사한 활동에 참여할 때 중요합니다.
- **Output Chain**: 나가는 연결의 규제에 전념합니다.

이러한 체인은 네트워크 트래픽의 정돈된 처리를 보장하며, 시스템으로 데이터의 흐름을 상세하게 규정하는 규칙을 지정할 수 있게 합니다.
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

### 설치 및 설정

To install Suricata, follow these steps:

1. Update the package manager: `sudo apt update`
2. Install Suricata: `sudo apt install suricata`
3. Configure Suricata by editing the configuration file located at `/etc/suricata/suricata.yaml`.

### Suricata 설치 및 설정

Suricata를 설치하려면 다음 단계를 따르십시오:

1. 패키지 관리자를 업데이트합니다: `sudo apt update`
2. Suricata를 설치합니다: `sudo apt install suricata`
3. `/etc/suricata/suricata.yaml`에 위치한 구성 파일을 편집하여 Suricata를 구성합니다.
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

[문서에서:](https://github.com/OISF/suricata/blob/master/doc/userguide/rules/intro.rst) 규칙/서명은 다음과 같이 구성됩니다:

* **액션**은 서명이 일치할 때 어떤 일이 발생하는지를 결정합니다.
* **헤더**는 규칙의 프로토콜, IP 주소, 포트 및 방향을 정의합니다.
* **규칙 옵션**은 규칙의 세부 사항을 정의합니다.
```bash
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP GET Request Containing Rule in URI"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"rule"; fast_pattern; classtype:bad-unknown; sid:123; rev:1;)
```
#### **유효한 동작은**

* alert - 경고 생성
* pass - 패킷의 추가 검사 중지
* **drop** - 패킷 삭제 및 경고 생성
* **reject** - 일치하는 패킷의 송신자에게 RST/ICMP 도달 불가능 오류 전송
* rejectsrc - _reject_와 동일
* rejectdst - 일치하는 패킷의 수신자에게 RST/ICMP 오류 패킷 전송
* rejectboth - 대화의 양쪽에 대해 RST/ICMP 오류 패킷 전송

#### **프로토콜**

* tcp (tcp 트래픽용)
* udp
* icmp
* ip (ip는 'all' 또는 'any'를 의미)
* _layer7 프로토콜_: http, ftp, tls, smb, dns, ssh... (자세한 내용은 [**문서**](https://suricata.readthedocs.io/en/suricata-6.0.0/rules/intro.html) 참조)

#### 소스 및 대상 주소

IP 범위, 부정 및 주소 목록을 지원합니다:

| 예제                          | 의미                                      |
| ------------------------------ | ---------------------------------------- |
| ! 1.1.1.1                      | 1.1.1.1을 제외한 모든 IP 주소             |
| !\[1.1.1.1, 1.1.1.2]           | 1.1.1.1과 1.1.1.2를 제외한 모든 IP 주소 |
| $HOME\_NET                     | yaml에서 설정한 HOME\_NET                 |
| \[$EXTERNAL\_NET, !$HOME\_NET] | EXTERNAL\_NET이면서 HOME\_NET이 아님      |
| \[10.0.0.0/24, !10.0.0.5]      | 10.0.0.0/24에서 10.0.0.5를 제외한 모든 IP 주소 |

#### 소스 및 대상 포트

포트 범위, 부정 및 포트 목록을 지원합니다.

| 예제         | 의미                                |
| --------------- | -------------------------------------- |
| any             | 모든 주소                            |
| \[80, 81, 82]   | 포트 80, 81 및 82                     |
| \[80: 82]       | 80부터 82까지 범위                  |
| \[1024: ]       | 1024부터 가장 높은 포트 번호까지 |
| !80             | 80을 제외한 모든 포트                      |
| \[80:100,!99]   | 80부터 100까지 범위, 단 99는 제외 |
| \[1:80,!\[2,4]] | 1부터 80까지 범위, 단 포트 2와 4는 제외 |

#### 방향

적용되는 통신 규칙의 방향을 지정할 수 있습니다:
```
source -> destination
source <> destination  (both directions)
```
#### 키워드

Suricata에는 수백 가지의 옵션이 있어 원하는 특정 패킷을 검색할 수 있습니다. 여기서는 흥미로운 내용이 발견되면 언급될 것입니다. 자세한 내용은 [문서](https://suricata.readthedocs.io/en/suricata-6.0.0/rules/index.html)를 확인하세요!
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

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

* **사이버 보안 회사**에서 일하시나요? **회사를 HackTricks에서 광고하고 싶으신가요**? 아니면 **PEASS의 최신 버전에 액세스하거나 HackTricks를 PDF로 다운로드**하고 싶으신가요? [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인해보세요!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견해보세요. 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter**에서 저를 **팔로우**하세요 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **[hacktricks repo](https://github.com/carlospolop/hacktricks)와 [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**에 PR을 제출하여 여러분의 해킹 기교를 공유해주세요.

</details>
