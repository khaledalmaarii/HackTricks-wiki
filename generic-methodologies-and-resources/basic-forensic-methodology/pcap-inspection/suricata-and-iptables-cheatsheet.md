# Suricata & Iptables spiekbrief

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Werk jy in 'n **cybersecurity-maatskappy**? Wil jy jou **maatskappy adverteer in HackTricks**? Of wil jy toegang hê tot die **nuutste weergawe van die PEASS of laai HackTricks in PDF af**? Kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Sluit aan by die** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** my op **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die [hacktricks repo](https://github.com/carlospolop/hacktricks) en [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Iptables

### Kettings

In iptables word lys van reëls wat kettings genoem word, sekwensieel verwerk. Daar is drie primêre kettings wat universeel teenwoordig is, met addisionele kettings soos NAT wat moontlik ondersteun word, afhangende van die vermoëns van die stelsel.

- **Input-ketting**: Word gebruik om die gedrag van inkomende verbindinge te bestuur.
- **Forward-ketting**: Word gebruik om inkomende verbindinge te hanteer wat nie bedoel is vir die plaaslike stelsel nie. Dit is tipies vir toestelle wat as roetingswerk optree, waar die ontvangste data bedoel is om na 'n ander bestemming gestuur te word. Hierdie ketting is hoofsaaklik relevant wanneer die stelsel betrokke is by roetering, NATing of soortgelyke aktiwiteite.
- **Output-ketting**: Word toegewy aan die regulering van uitgaande verbindinge.

Hierdie kettings verseker die ordelike verwerking van netwerkverkeer, wat die spesifikasie van gedetailleerde reëls moontlik maak wat die vloei van data in, deur en uit 'n stelsel beheer.
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

### Installeer & Konfigurasie

```bash
# Installeer Suricata
sudo apt-get install suricata

# Skep 'n nuwe konfigurasie lêer
sudo cp /etc/suricata/suricata.yaml /etc/suricata/suricata.yaml.bak

# Pas die konfigurasie lêer aan
sudo nano /etc/suricata/suricata.yaml

# Stel die volgende waardes in:
    - HOME_NET: jou_netwerk
    - EXTERNAL_NET: enige
    - RULES_DIR: /etc/suricata/rules
    - LOG_DIR: /var/log/suricata/

# Stoor die veranderinge en sluit die lêer

# Skep 'n nuwe reëls gids
sudo mkdir /etc/suricata/rules

# Skep 'n nuwe reëls lêer
sudo touch /etc/suricata/rules/local.rules

# Herlaai Suricata se konfigurasie
sudo suricata-update enable-source oisf/trafficid
sudo suricata-update update-sources
sudo suricata-update

# Begin Suricata
sudo suricata -c /etc/suricata/suricata.yaml -i jou_interface
```

### Iptables

```bash
# Skep 'n nuwe iptables reël
sudo iptables -A OUTPUT -p tcp --dport 80 -j NFQUEUE --queue-num 1

# Skep 'n nuwe iptables reël vir HTTPS
sudo iptables -A OUTPUT -p tcp --dport 443 -j NFQUEUE --queue-num 1

# Skep 'n nuwe iptables reël vir DNS
sudo iptables -A OUTPUT -p udp --dport 53 -j NFQUEUE --queue-num 1

# Skep 'n nuwe iptables reël vir ICMP
sudo iptables -A OUTPUT -p icmp -j NFQUEUE --queue-num 1

# Skep 'n nuwe iptables reël vir SSH
sudo iptables -A OUTPUT -p tcp --dport 22 -j NFQUEUE --queue-num 1

# Skep 'n nuwe iptables reël vir RDP
sudo iptables -A OUTPUT -p tcp --dport 3389 -j NFQUEUE --queue-num 1

# Skep 'n nuwe iptables reël vir FTP
sudo iptables -A OUTPUT -p tcp --dport 21 -j NFQUEUE --queue-num 1

# Skep 'n nuwe iptables reël vir Telnet
sudo iptables -A OUTPUT -p tcp --dport 23 -j NFQUEUE --queue-num 1

# Skep 'n nuwe iptables reël vir SMTP
sudo iptables -A OUTPUT -p tcp --dport 25 -j NFQUEUE --queue-num 1

# Skep 'n nuwe iptables reël vir POP3
sudo iptables -A OUTPUT -p tcp --dport 110 -j NFQUEUE --queue-num 1

# Skep 'n nuwe iptables reël vir IMAP
sudo iptables -A OUTPUT -p tcp --dport 143 -j NFQUEUE --queue-num 1

# Skep 'n nuwe iptables reël vir SNMP
sudo iptables -A OUTPUT -p udp --dport 161 -j NFQUEUE --queue-num 1

# Skep 'n nuwe iptables reël vir NTP
sudo iptables -A OUTPUT -p udp --dport 123 -j NFQUEUE --queue-num 1

# Skep 'n nuwe iptables reël vir MySQL
sudo iptables -A OUTPUT -p tcp --dport 3306 -j NFQUEUE --queue-num 1

# Skep 'n nuwe iptables reël vir PostgreSQL
sudo iptables -A OUTPUT -p tcp --dport 5432 -j NFQUEUE --queue-num 1

# Skep 'n nuwe iptables reël vir MSSQL
sudo iptables -A OUTPUT -p tcp --dport 1433 -j NFQUEUE --queue-num 1

# Skep 'n nuwe iptables reël vir Oracle
sudo iptables -A OUTPUT -p tcp --dport 1521 -j NFQUEUE --queue-num 1

# Skep 'n nuwe iptables reël vir VNC
sudo iptables -A OUTPUT -p tcp --dport 5900 -j NFQUEUE --queue-num 1

# Skep 'n nuwe iptables reël vir SMB
sudo iptables -A OUTPUT -p tcp --dport 445 -j NFQUEUE --queue-num 1

# Skep 'n nuwe iptables reël vir LDAP
sudo iptables -A OUTPUT -p tcp --dport 389 -j NFQUEUE --queue-num 1

# Skep 'n nuwe iptables reël vir FTPS
sudo iptables -A OUTPUT -p tcp --dport 990 -j NFQUEUE --queue-num 1

# Skep 'n nuwe iptables reël vir SFTP
sudo iptables -A OUTPUT -p tcp --dport 22 -j NFQUEUE --queue-num 1

# Skep 'n nuwe iptables reël vir IRC
sudo iptables -A OUTPUT -p tcp --dport 6667 -j NFQUEUE --queue-num 1

# Skep 'n nuwe iptables reël vir Rsync
sudo iptables -A OUTPUT -p tcp --dport 873 -j NFQUEUE --queue-num 1

# Skep 'n nuwe iptables reël vir DNSSEC
sudo iptables -A OUTPUT -p tcp --dport 853 -j NFQUEUE --queue-num 1

# Skep 'n nuwe iptables reël vir DHCP
sudo iptables -A OUTPUT -p udp --dport 67:68 -j NFQUEUE --queue-num 1

# Skep 'n nuwe iptables reël vir IRC
sudo iptables -A OUTPUT -p tcp --dport 194 -j NFQUEUE --queue-num 1

# Skep 'n nuwe iptables reël vir IRC
sudo iptables -A OUTPUT -p tcp --dport 6660:6669 -j NFQUEUE --queue-num 1

# Skep 'n nuwe iptables reël vir IRC
sudo iptables -A OUTPUT -p tcp --dport 7000 -j NFQUEUE --queue-num 1

# Skep 'n nuwe iptables reël vir IRC
sudo iptables -A OUTPUT -p tcp --dport 8000 -j NFQUEUE --queue-num 1

# Skep 'n nuwe iptables reël vir IRC
sudo iptables -A OUTPUT -p tcp --dport 9000 -j NFQUEUE --queue-num 1

# Skep 'n nuwe iptables reël vir IRC
sudo iptables -A OUTPUT -p tcp --dport 9001 -j NFQUEUE --queue-num 1

# Skep 'n nuwe iptables reël vir IRC
sudo iptables -A OUTPUT -p tcp --dport 9009 -j NFQUEUE --queue-num 1

# Skep 'n nuwe iptables reël vir IRC
sudo iptables -A OUTPUT -p tcp --dport 9010 -j NFQUEUE --queue-num 1

# Skep 'n nuwe iptables reël vir IRC
sudo iptables -A OUTPUT -p tcp --dport 9020 -j NFQUEUE --queue-num 1

# Skep 'n nuwe iptables reël vir IRC
sudo iptables -A OUTPUT -p tcp --dport 9030 -j NFQUEUE --queue-num 1

# Skep 'n nuwe iptables reël vir IRC
sudo iptables -A OUTPUT -p tcp --dport 9040 -j NFQUEUE --queue-num 1

# Skep 'n nuwe iptables reël vir IRC
sudo iptables -A OUTPUT -p tcp --dport 9050 -j NFQUEUE --queue-num 1

# Skep 'n nuwe iptables reël vir IRC
sudo iptables -A OUTPUT -p tcp --dport 9060 -j NFQUEUE --queue-num 1

# Skep 'n nuwe iptables reël vir IRC
sudo iptables -A OUTPUT -p tcp --dport 9070 -j NFQUEUE --queue-num 1

# Skep 'n nuwe iptables reël vir IRC
sudo iptables -A OUTPUT -p tcp --dport 9080 -j NFQUEUE --queue-num 1

# Skep 'n nuwe iptables reël vir IRC
sudo iptables -A OUTPUT -p tcp --dport 9090 -j NFQUEUE --queue-num 1

# Skep 'n nuwe iptables reël vir IRC
sudo iptables -A OUTPUT -p tcp --dport 9100 -j NFQUEUE --queue-num 1

# Skep 'n nuwe iptables reël vir IRC
sudo iptables -A OUTPUT -p tcp --dport 9110 -j NFQUEUE --queue-num 1

# Skep 'n nuwe iptables reël vir IRC
sudo iptables -A OUTPUT -p tcp --dport 9120 -j NFQUEUE --queue-num 1

# Skep 'n nuwe iptables reël vir IRC
sudo iptables -A OUTPUT -p tcp --dport 9130 -j NFQUEUE --queue-num 1

# Skep 'n nuwe iptables reël vir IRC
sudo iptables -A OUTPUT -p tcp --dport 9140 -j NFQUEUE --queue-num 1

# Skep 'n nuwe iptables reël vir IRC
sudo iptables -A OUTPUT -p tcp --dport 9150 -j NFQUEUE --queue-num 1

# Skep 'n nuwe iptables reël vir IRC
sudo iptables -A OUTPUT -p tcp --dport 9160 -j NFQUEUE --queue-num 1

# Skep 'n nuwe iptables reël vir IRC
sudo iptables -A OUTPUT -p tcp --dport 9170 -j NFQUEUE --queue-num 1

# Skep 'n nuwe iptables reël vir IRC
sudo iptables -A OUTPUT -p tcp --dport 9180 -j NFQUEUE --queue-num 1

# Skep 'n nuwe iptables reël vir IRC
sudo iptables -A OUTPUT -p tcp --dport 9190 -j NFQUEUE --queue-num 1

# Skep 'n nuwe iptables reël vir IRC
sudo iptables -A OUTPUT -p tcp --dport 9200 -j NFQUEUE --queue-num 1

# Skep 'n nuwe iptables reël vir IRC
sudo iptables -A OUTPUT -p tcp --dport 9210 -j NFQUEUE --queue-num 1

# Skep 'n nuwe iptables reël vir IRC
sudo iptables -A OUTPUT -p tcp --dport 9220 -j NFQUEUE --queue-num 1

# Skep 'n nuwe iptables reël vir IRC
sudo iptables -A OUTPUT -p tcp --dport 9230 -j NFQUEUE --queue-num 1

# Skep 'n nuwe iptables reël vir IRC
sudo iptables -A OUTPUT -p tcp --dport 9240 -j NFQUEUE --queue-num 1

# Skep 'n nuwe iptables reël vir IRC
sudo iptables -A OUTPUT -p tcp --dport 9250 -j NFQUEUE --queue-num 1

# Skep 'n nuwe iptables reël vir IRC
sudo iptables -A OUTPUT -p tcp --dport 9260 -j NFQUEUE --queue-num 1

# Skep 'n nuwe iptables reël vir IRC
sudo iptables -A OUTPUT -p tcp --dport 9270 -j NFQUEUE --queue-num 1

# Skep 'n nuwe iptables reël vir IRC
sudo iptables -A OUTPUT -p tcp --dport 9280 -j NFQUEUE --queue-num 1

# Skep 'n nuwe iptables reël vir IRC
sudo iptables -A OUTPUT -p tcp --dport 9290 -j NFQUEUE --queue-num 1

# Skep 'n nuwe iptables reël vir IRC
sudo iptables -A OUTPUT -p tcp --dport 9300 -j NFQUEUE --queue-num 1

# Skep 'n nuwe iptables reël vir IRC
sudo iptables -A OUTPUT -p tcp --dport 9310 -j NFQUEUE --queue-num 1

# Skep 'n nuwe iptables reël vir IRC
sudo iptables -A OUTPUT -p tcp --dport 9320 -j NFQUEUE --queue-num 1

# Skep 'n nuwe iptables reël vir IRC
sudo iptables -A OUTPUT -p tcp --dport 9330 -j NFQUEUE --queue-num 1

# Skep 'n nuwe iptables reël vir IRC
sudo iptables -A OUTPUT -p tcp --dport 9340 -j NFQUEUE --queue-num 1

# Skep 'n nuwe iptables reël vir IRC
sudo iptables -A OUTPUT -p tcp --dport 9350 -j NFQUEUE --queue-num 1

# Skep 'n nuwe iptables reël vir IRC
sudo iptables -A OUTPUT -p tcp --dport 9360 -j NFQUEUE --queue-num 1

# Skep 'n nuwe iptables reël vir IRC
sudo iptables -A OUTPUT -p tcp --dport 9370 -j NFQUEUE --queue-num 1

# Skep 'n nuwe iptables reël vir IRC
sudo iptables -A OUTPUT -p tcp --dport 9380 -j NFQUEUE --queue-num 1

# Skep 'n nuwe iptables reël vir IRC
sudo iptables -A OUTPUT -p tcp --dport 9390 -j NFQUEUE --queue-num 1

# Skep 'n nuwe iptables reël vir IRC
sudo iptables -A OUTPUT -p tcp --dport 9400 -j NFQUEUE --queue-num 1

# Skep 'n nuwe iptables reël vir IRC
sudo iptables -A OUTPUT -p tcp --dport 9410 -j NFQUEUE --queue-num 1

# Skep 'n nuwe iptables reël vir IRC
sudo iptables -A OUTPUT -p tcp --dport 9420 -j NFQUEUE --queue-num 1

# Skep 'n nuwe iptables reël vir IRC
sudo iptables -A OUTPUT -p tcp --dport 9430 -j NFQUEUE --queue-num 1

# Skep 'n nuwe iptables reël vir IRC
sudo iptables -A OUTPUT -p tcp --dport 9440 -j NFQUEUE --queue-num 1

# Skep 'n nuwe iptables reël vir IRC
sudo iptables -A OUTPUT -p tcp --dport 9450 -j NFQUEUE --queue-num 1

# Skep 'n nuwe iptables reël vir IRC
sudo iptables -A OUTPUT -p tcp --dport 9460 -j NFQUEUE --queue-num 1

# Skep 'n nuwe iptables reël vir IRC
sudo iptables -A OUTPUT -p tcp --dport 9470 -j NFQUEUE --queue-num 1

# Skep 'n nuwe iptables reël vir IRC
sudo iptables -A OUTPUT -p tcp --dport 9480 -j NFQUEUE --queue-num 1

# Skep 'n nuwe iptables reël vir IRC
sudo iptables -A OUTPUT -p tcp --dport 9490 -j NFQUEUE --queue-num 1

# Skep 'n nuwe iptables reël vir IRC
sudo iptables -A OUTPUT -p tcp --dport 9500 -j NFQUEUE --queue-num 1

# Skep 'n nuwe iptables reël vir IRC
sudo iptables -A OUTPUT -p tcp --dport 9510 -j NFQUEUE --queue-num 1

# Skep 'n nuwe iptables reël vir IRC
sudo iptables -A OUTPUT -p tcp --dport 9520 -j NFQUEUE --queue-num 1

# Skep 'n nuwe iptables reël vir IRC
sudo iptables -A OUTPUT -p tcp --dport 9530 -j NFQUEUE --queue-num 1

# Skep 'n nuwe iptables reël vir IRC
sudo iptables -A OUTPUT -p tcp --dport 9540 -j NFQUEUE --queue-num 1

# Skep 'n nuwe iptables reël vir IRC
sudo iptables -A OUTPUT -p tcp --dport 9550 -j NFQUEUE --queue-num 1

# Skep 'n nuwe iptables reël vir IRC
sudo iptables -A OUTPUT -p tcp --dport 9560 -j NFQUEUE --queue-num 1

# Skep 'n nuwe iptables reël vir IRC
sudo iptables -A OUTPUT -p tcp --dport 9570 -j NFQUEUE --queue-num 1

# Skep 'n nuwe iptables reël vir IRC
sudo iptables -A OUTPUT -p tcp --dport 9580 -j NFQUEUE --queue-num 1

# Skep 'n nuwe iptables reël vir IRC
sudo iptables -A OUTPUT -p tcp --dport 9590 -j NFQUEUE --queue-num 1

# Skep 'n nuwe iptables reël vir IRC
sudo iptables -A OUTPUT -p tcp --dport 9600 -j NFQUEUE --
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
### Reëlsdefinisies

[Van die dokumentasie:](https://github.com/OISF/suricata/blob/master/doc/userguide/rules/intro.rst) 'n Reël/handtekening bestaan uit die volgende:

* Die **aksie**, bepaal wat gebeur wanneer die handtekening ooreenstem.
* Die **kop**, definieer die protokol, IP-adresse, poorte en rigting van die reël.
* Die **reël-opsies**, definieer die spesifieke van die reël.
```bash
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP GET Request Containing Rule in URI"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"rule"; fast_pattern; classtype:bad-unknown; sid:123; rev:1;)
```
#### **Geldig aksies is**

* waarskuwing - genereer 'n waarskuwing
* slaag - stop verdere inspeksie van die pakkie
* **verwerp** - verwerp pakkie en genereer waarskuwing
* **afwys** - stuur RST/ICMP onbereikbare fout na die sender van die ooreenstemmende pakkie.
* verwerpbron - dieselfde as net _afwys_
* verwerpdoel - stuur RST/ICMP foutpakkie na die ontvanger van die ooreenstemmende pakkie.
* verwerpbeide - stuur RST/ICMP foutpakkies na beide kante van die gesprek.

#### **Protokolle**

* tcp (vir tcp-verkeer)
* udp
* icmp
* ip (ip staan vir 'alles' of 'enige')
* _laag7-protokolle_: http, ftp, tls, smb, dns, ssh... (meer in die [**dokumentasie**](https://suricata.readthedocs.io/en/suricata-6.0.0/rules/intro.html))

#### Bron- en Bestemmingsadressering

Dit ondersteun IP-reekse, negasies en 'n lys van adresse:

| Voorbeeld                        | Betekenis                                  |
| ------------------------------ | ---------------------------------------- |
| ! 1.1.1.1                      | Elke IP-adres behalwe 1.1.1.1             |
| !\[1.1.1.1, 1.1.1.2]           | Elke IP-adres behalwe 1.1.1.1 en 1.1.1.2 |
| $HOME\_NET                     | Jou instelling van HOME\_NET in yaml        |
| \[$EXTERNAL\_NET, !$HOME\_NET] | EXTERNAL\_NET en nie HOME\_NET          |
| \[10.0.0.0/24, !10.0.0.5]      | 10.0.0.0/24 behalwe vir 10.0.0.5          |

#### Bron- en Bestemmingspoorte

Dit ondersteun poortreeks, negasies en lys van poorte

| Voorbeeld         | Betekenis                                |
| --------------- | -------------------------------------- |
| enige             | enige adres                            |
| \[80, 81, 82]   | poort 80, 81 en 82                     |
| \[80: 82]       | Reeks van 80 tot 82                  |
| \[1024: ]       | Vanaf 1024 tot die hoogste poortnommer |
| !80             | Elke poort behalwe 80                      |
| \[80:100,!99]   | Reeks van 80 tot 100 maar 99 uitgesluit |
| \[1:80,!\[2,4]] | Reeks van 1-80, behalwe poorte 2 en 4  |

#### Rigting

Dit is moontlik om die rigting van die kommunikasiereël aan te dui wat toegepas word:
```
source -> destination
source <> destination  (both directions)
```
#### Sleutelwoorde

Daar is **honderde opsies** beskikbaar in Suricata om te soek na die **spesifieke pakkie** waarna jy soek, hier sal genoem word as iets interessant gevind word. Kyk na die [**dokumentasie**](https://suricata.readthedocs.io/en/suricata-6.0.0/rules/index.html) vir meer inligting!
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

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Werk jy in 'n **cybersecurity-maatskappy**? Wil jy jou **maatskappy geadverteer sien in HackTricks**? Of wil jy toegang hê tot die **nuutste weergawe van die PEASS of laai HackTricks in PDF af**? Kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Sluit aan by die** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** my op **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die [hacktricks repo](https://github.com/carlospolop/hacktricks) en [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
