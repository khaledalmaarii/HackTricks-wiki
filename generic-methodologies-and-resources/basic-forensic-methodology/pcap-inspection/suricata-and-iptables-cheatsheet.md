# Suricata & Iptables cheatsheet

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka mwanzo hadi kuwa bingwa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Je, unafanya kazi katika **kampuni ya usalama wa mtandao**? Je, ungependa kuona **kampuni yako ikionekana katika HackTricks**? Au ungependa kupata ufikiaji wa **toleo jipya zaidi la PEASS au kupakua HackTricks kwa PDF**? Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* **Jiunge na** [**💬**](https://emojipedia.org/speech-balloon/) [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **nifuatilie** kwenye **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye [repo ya hacktricks](https://github.com/carlospolop/hacktricks) na [repo ya hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Iptables

### Chains

Katika iptables, orodha ya sheria inayojulikana kama chains hupangwa kwa utaratibu. Miongoni mwao, kuna chains tatu kuu ambazo zipo kila mahali, na nyingine zaidi kama NAT zinaweza kuwa zinasaidiwa kulingana na uwezo wa mfumo.

- **Chain ya Input**: Hutumiwa kusimamia tabia ya uhusiano unaokuja.
- **Chain ya Forward**: Hutumiwa kushughulikia uhusiano unaokuja ambao sio kwa ajili ya mfumo wa ndani. Hii ni kawaida kwa vifaa vinavyofanya kazi kama rutuba, ambapo data iliyopokelewa inalenga kupelekwa kwa marudio mengine. Chain hii ni muhimu hasa wakati mfumo unahusika katika kusambaza, kubadilisha anwani ya IP, au shughuli kama hizo.
- **Chain ya Output**: Imetengwa kwa udhibiti wa uhusiano unaotoka.

Chains hizi zinahakikisha usindikaji wa utaratibu wa trafiki ya mtandao, kuruhusu kuweka sheria za kina zinazosimamia mtiririko wa data ndani, kupitia, na nje ya mfumo.
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

### Sakinisha na Sanidi

```bash
# Install Suricata
sudo apt-get install suricata

# Configure Suricata
sudo nano /etc/suricata/suricata.yaml
```

### Enable IPS Mode

```bash
# Edit Suricata configuration file
sudo nano /etc/suricata/suricata.yaml

# Uncomment the following line
# mode: inline
```

### Start Suricata

```bash
sudo suricata -c /etc/suricata/suricata.yaml -i eth0
```

## iptables

### Enable Packet Logging

```bash
# Enable packet logging
sudo iptables -A INPUT -j LOG
sudo iptables -A OUTPUT -j LOG
sudo iptables -A FORWARD -j LOG
```

### View Packet Logs

```bash
# View packet logs
sudo tail -f /var/log/kern.log
```

### Disable Packet Logging

```bash
# Disable packet logging
sudo iptables -D INPUT -j LOG
sudo iptables -D OUTPUT -j LOG
sudo iptables -D FORWARD -j LOG
```

### Clear iptables Rules

```bash
# Clear iptables rules
sudo iptables -F
sudo iptables -X
sudo iptables -Z
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
### Maelezo ya Sheria

[Kutoka kwa nyaraka:](https://github.com/OISF/suricata/blob/master/doc/userguide/rules/intro.rst) Sheria/ishara inajumuisha yafuatayo:

* **Hatua**, inaamua kinachotokea wakati ishara inalingana.
* **Kichwa**, kinatambua itifaki, anwani za IP, bandari, na mwelekeo wa sheria.
* **Chaguo za sheria**, zinatambua maelezo maalum ya sheria.
```bash
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP GET Request Containing Rule in URI"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"rule"; fast_pattern; classtype:bad-unknown; sid:123; rev:1;)
```
#### **Vitendo halali ni**

* tahadhari - toa tahadhari
* pita - acha ukaguzi zaidi wa pakiti
* **ondoa** - ondoa pakiti na toa tahadhari
* **kataa** - tuma RST/ICMP kosa lisilopatikana kwa mtumaji wa pakiti inayolingana.
* kataasrc - sawa na tu _kataa_
* kataadst - tuma pakiti ya kosa ya RST/ICMP kwa mpokeaji wa pakiti inayolingana.
* kataote - tuma pakiti za kosa za RST/ICMP kwa pande zote za mazungumzo.

#### **Itifaki**

* tcp (kwa trafiki ya tcp)
* udp
* icmp
* ip (ip inasimama kwa 'zote' au 'yoyote')
* _itifaki za safu ya 7_: http, ftp, tls, smb, dns, ssh... (zaidi katika [**nyaraka**](https://suricata.readthedocs.io/en/suricata-6.0.0/rules/intro.html))

#### Anwani za Chanzo na Kichwa

Inasaidia safu za IP, negations na orodha ya anwani:

| Mfano                          | Maana                                    |
| ------------------------------ | ---------------------------------------- |
| ! 1.1.1.1                      | Kila anwani ya IP isipokuwa 1.1.1.1       |
| !\[1.1.1.1, 1.1.1.2]           | Kila anwani ya IP isipokuwa 1.1.1.1 na 1.1.1.2 |
| $HOME\_NET                     | Mipangilio yako ya HOME\_NET katika yaml  |
| \[$EXTERNAL\_NET, !$HOME\_NET] | EXTERNAL\_NET na sio HOME\_NET            |
| \[10.0.0.0/24, !10.0.0.5]      | 10.0.0.0/24 isipokuwa 10.0.0.5           |

#### Bandari za Chanzo na Kichwa

Inasaidia safu za bandari, negations na orodha ya bandari

| Mfano         | Maana                                |
| --------------- | -------------------------------------- |
| any             | anwani yoyote                            |
| \[80, 81, 82]   | bandari 80, 81 na 82                     |
| \[80: 82]       | Safu kutoka 80 hadi 82                  |
| \[1024: ]       | Kutoka 1024 hadi nambari ya bandari ya juu zaidi |
| !80             | Kila bandari isipokuwa 80                      |
| \[80:100,!99]   | Safu kutoka 80 hadi 100 lakini 99 imeondolewa |
| \[1:80,!\[2,4]] | Safu kutoka 1-80, isipokuwa bandari 2 na 4  |

#### Mwelekeo

Inawezekana kuonyesha mwelekeo wa sheria ya mawasiliano inayotumiwa:
```
source -> destination
source <> destination  (both directions)
```
#### Maneno muhimu

Kuna **chaguo nyingi** zinazopatikana katika Suricata ili kutafuta **pakiti maalum** unayotafuta, hapa itatajwa ikiwa kitu chochote cha kuvutia kitapatikana. Angalia [**nyaraka**](https://suricata.readthedocs.io/en/suricata-6.0.0/rules/index.html) kwa maelezo zaidi!
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

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

* Je, unafanya kazi katika **kampuni ya usalama wa mtandao**? Je, ungependa kuona **kampuni yako ikionekana katika HackTricks**? Au ungependa kupata ufikiaji wa **toleo jipya zaidi la PEASS au kupakua HackTricks kwa muundo wa PDF**? Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* **Jiunge na** [**💬**](https://emojipedia.org/speech-balloon/) [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **nifuatilie** kwenye **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye repo ya [hacktricks](https://github.com/carlospolop/hacktricks) na repo ya [hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
