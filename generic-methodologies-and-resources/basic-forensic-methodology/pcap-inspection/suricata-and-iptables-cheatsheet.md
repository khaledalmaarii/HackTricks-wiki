# Suricata और Iptables चीटशीट

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* क्या आप **साइबर सुरक्षा कंपनी** में काम करते हैं? क्या आप अपनी **कंपनी का विज्ञापन HackTricks में देखना चाहते हैं**? या क्या आप **PEASS के नवीनतम संस्करण या HackTricks को PDF में डाउनलोड करना चाहते हैं**? [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) की जाँच करें!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) की खोज करें, हमारा विशेष [**NFTs**](https://opensea.io/collection/the-peass-family) संग्रह।
* [**आधिकारिक PEASS और HackTricks swag**](https://peass.creator-spring.com) प्राप्त करें।
* **शामिल हों** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) या **मुझे** **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)** पर** **फॉलो** करें।
* **हैकिंग ट्रिक्स साझा करें, [hacktricks रेपो](https://github.com/carlospolop/hacktricks) और [hacktricks-cloud रेपो](https://github.com/carlospolop/hacktricks-cloud) में PR जमा करके**।

</details>

## Iptables

### श्रृंखलाएँ

Iptables में, नियमों की सूचियों को श्रृंखलाएँ कहा जाता है जो क्रमश: प्रसंस्कृत किए जाते हैं। इनमें से, तीन मुख्य श्रृंखलाएँ सार्वत्रिक रूप से मौजूद होती हैं, जिनमें सिस्टम की क्षमताओं पर निर्भर करता है कि क्या अतिरिक्त श्रृंखलाएँ जैसे NAT समर्थित हो सकती हैं।

- **Input श्रृंखला**: आने वाली कनेक्शन के व्यवहार का प्रबंधन करने के लिए प्रयोग किया जाता है।
- **Forward श्रृंखला**: स्थानीय सिस्टम के लिए निर्धारित न होने वाली आने वाली कनेक्शनों का प्रबंधन करने के लिए प्रयोग किया जाता है। यह उन उपकरणों के लिए सामान्य है जो राउटर के रूप में कार्य कर रहे होते हैं, जहां प्राप्त डेटा को दूसरे गंतव्य की ओर फॉरवर्ड किया जाना है। यह श्रृंखला मुख्य रूप से तब महत्वपूर्ण होती है जब सिस्टम रूटिंग, NATing, या समान कार्यों में शामिल है।
- **Output श्रृंखला**: बाहरी कनेक्शनों के नियामक के लिए समर्पित है।

ये श्रृंखलाएँ नेटवर्क ट्रैफिक की व्यवस्थित प्रसंस्करण सुनिश्चित करती हैं, जिससे डेटा के प्रवाह को विस्तृत नियमों के अनुसार नियंत्रित किया जा सकता है जो सिस्टम में द्वारा, के माध्यम से, और सिस्टम से बाहर जाने का नियमन करते हैं।
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
## सुरिकाटा

### स्थापित करें और विन्यास
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
### नियम परिभाषाएँ

[दस्तावेज़ से:](https://github.com/OISF/suricata/blob/master/doc/userguide/rules/intro.rst) एक नियम/हस्ताक्षर निम्नलिखित से मिलकर बनता है:

* **क्रिया**, जब हस्ताक्षर मेल खाता है तो क्या होता है, यह निर्धारित करती है।
* **हैडर**, प्रोटोकॉल, आईपी पते, पोर्ट और नियम की दिशा को परिभाषित करता है।
* **नियम विकल्प**, नियम की विशेषताएँ परिभाषित करते हैं।
```bash
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP GET Request Containing Rule in URI"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"rule"; fast_pattern; classtype:bad-unknown; sid:123; rev:1;)
```
#### **मान्य क्रियाएँ हैं**

* alert - एलर्ट उत्पन्न करें
* pass - पैकेट की और जांच रोकें
* **drop** - पैकेट को ड्रॉप करें और एलर्ट उत्पन्न करें
* **reject** - मेल खाते पैकेट के प्रेषक को RST/ICMP अनुपलब्धता त्रुटि भेजें।
* rejectsrc - बस _reject_ के रूप में
* rejectdst - मेल खाते पैकेट के प्राप्तकर्ता को RST/ICMP त्रुटि पैकेट भेजें।
* rejectboth - बातचीत के दोनों पक्षों को RST/ICMP त्रुटि पैकेट भेजें।

#### **प्रोटोकॉल**

* tcp (tcp-ट्रैफिक के लिए)
* udp
* icmp
* ip (ip 'सभी' या 'कोई' के लिए है)
* _लेयर7 प्रोटोकॉल_: http, ftp, tls, smb, dns, ssh... (अधिक जानकारी के लिए [**दस्तावेज**](https://suricata.readthedocs.io/en/suricata-6.0.0/rules/intro.html) देखें)

#### स्रोत और गंतव्य पते

यह IP रेंज, नकारात्मक और पतों की सूची का समर्थन करता है:

| उदाहरण                        | अर्थ                                  |
| ------------------------------ | ---------------------------------------- |
| ! 1.1.1.1                      | 1.1.1.1 को छोड़कर हर IP पता             |
| !\[1.1.1.1, 1.1.1.2]           | 1.1.1.1 और 1.1.1.2 को छोड़कर हर IP पता |
| $HOME\_NET                     | आपकी yaml में HOME\_NET की सेटिंग     |
| \[$EXTERNAL\_NET, !$HOME\_NET] | EXTERNAL\_NET और HOME\_NET नहीं          |
| \[10.0.0.0/24, !10.0.0.5]      | 10.0.0.0/24 केवल 10.0.0.5 को छोड़कर          |

#### स्रोत और गंतव्य बंदरगाह

यह पोर्ट रेंज, नकारात्मक और पोर्ट की सूचियों का समर्थन करता है

| उदाहरण         | अर्थ                                |
| --------------- | -------------------------------------- |
| any             | कोई भी पता                          |
| \[80, 81, 82]   | पोर्ट 80, 81 और 82                  |
| \[80: 82]       | 80 से 82 तक का सीमा                 |
| \[1024: ]       | 1024 से सबसे उच्च पोर्ट-नंबर तक |
| !80             | 80 को छोड़कर हर पोर्ट               |
| \[80:100,!99]   | 80 से 100 तक का सीमा, लेकिन 99 छोड़ें |
| \[1:80,!\[2,4]] | 1-80 तक का सीमा, 2 और 4 को छोड़कर  | 

#### दिशा

संचार नियम के लागू होने की दिशा को निर्दिष्ट करना संभव है:
```
source -> destination
source <> destination  (both directions)
```
#### कीवर्ड

Suricata में **सैकड़ों विकल्प** उपलब्ध हैं जिनका उपयोग **निश्चित पैकेट** की खोज के लिए किया जा सकता है, यहाँ यह उल्लेख किया जाएगा अगर कुछ दिलचस्प मिलता है। अधिक जानकारी के लिए [**दस्तावेज़ीकरण**](https://suricata.readthedocs.io/en/suricata-6.0.0/rules/index.html) देखें!
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

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* क्या आप **साइबर सुरक्षा कंपनी** में काम करते हैं? क्या आप अपनी **कंपनी का विज्ञापन HackTricks में देखना चाहते हैं**? या क्या आप **PEASS के नवीनतम संस्करण या HackTricks को PDF में डाउनलोड करना चाहते हैं**? [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) की जाँच करें!
* हमारे विशेष [**NFTs**](https://opensea.io/collection/the-peass-family) संग्रह **The PEASS Family** की खोज करें
* [**आधिकारिक PEASS & HackTricks swag**](https://peass.creator-spring.com) प्राप्त करें
* **शामिल हों** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) या **मुझे** **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)** पर फॉलो** करें।
* **हैकिंग ट्रिक्स साझा करें** [hacktricks रेपो](https://github.com/carlospolop/hacktricks) और [hacktricks-cloud रेपो](https://github.com/carlospolop/hacktricks-cloud)** को PR जमा करके।

</details>
