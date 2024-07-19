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

Iptables में, नियमों की सूचियाँ जिन्हें चेन कहा जाता है, अनुक्रमिक रूप से संसाधित की जाती हैं। इनमें से, तीन प्राथमिक चेन सार्वभौमिक रूप से उपस्थित होते हैं, जबकि NAT जैसी अतिरिक्त चेन सिस्टम की क्षमताओं के आधार पर संभावित रूप से समर्थित होती हैं।

- **Input Chain**: आने वाले कनेक्शनों के व्यवहार को प्रबंधित करने के लिए उपयोग किया जाता है।
- **Forward Chain**: उन आने वाले कनेक्शनों को संभालने के लिए उपयोग किया जाता है जो स्थानीय सिस्टम के लिए नहीं होते। यह उन उपकरणों के लिए सामान्य है जो राउटर के रूप में कार्य करते हैं, जहाँ प्राप्त डेटा को किसी अन्य गंतव्य पर अग्रेषित किया जाना होता है। यह चेन मुख्य रूप से तब प्रासंगिक होती है जब सिस्टम राउटिंग, NATिंग, या समान गतिविधियों में शामिल होता है।
- **Output Chain**: बाहर जाने वाले कनेक्शनों के विनियमन के लिए समर्पित है।

ये चेन नेटवर्क ट्रैफ़िक के व्यवस्थित प्रसंस्करण को सुनिश्चित करते हैं, जिससे डेटा के प्रवाह को सिस्टम में, उसके माध्यम से, और बाहर निर्दिष्ट करने के लिए विस्तृत नियमों को निर्धारित किया जा सकता है।
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

### इंस्टॉल और कॉन्फ़िगर
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

[दस्तावेज़ों से:](https://github.com/OISF/suricata/blob/master/doc/userguide/rules/intro.rst) एक नियम/सिग्नेचर निम्नलिखित से मिलकर बनता है:

* **क्रिया**, यह निर्धारित करती है कि जब सिग्नेचर मेल खाता है तो क्या होता है।
* **हेडर**, नियम के प्रोटोकॉल, आईपी पते, पोर्ट और दिशा को परिभाषित करता है।
* **नियम विकल्प**, नियम की विशिष्टताओं को परिभाषित करते हैं।
```bash
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP GET Request Containing Rule in URI"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"rule"; fast_pattern; classtype:bad-unknown; sid:123; rev:1;)
```
#### **मान्य क्रियाएँ हैं**

* alert - एक अलर्ट उत्पन्न करें
* pass - पैकेट की आगे की जांच रोकें
* **drop** - पैकेट को ड्रॉप करें और अलर्ट उत्पन्न करें
* **reject** - मेल खाने वाले पैकेट के प्रेषक को RST/ICMP अप्राप्य त्रुटि भेजें।
* rejectsrc - बस _reject_ के समान
* rejectdst - मेल खाने वाले पैकेट के रिसीवर को RST/ICMP त्रुटि पैकेट भेजें।
* rejectboth - बातचीत के दोनों पक्षों को RST/ICMP त्रुटि पैकेट भेजें।

#### **प्रोटोकॉल**

* tcp (tcp-traffic के लिए)
* udp
* icmp
* ip (ip का अर्थ है 'सभी' या 'कोई भी')
* _लेयर7 प्रोटोकॉल_: http, ftp, tls, smb, dns, ssh... (अधिक जानकारी [**docs**](https://suricata.readthedocs.io/en/suricata-6.0.0/rules/intro.html) में)

#### स्रोत और गंतव्य पते

यह IP रेंज, नकारात्मकता और पते की सूची का समर्थन करता है:

| उदाहरण                          | अर्थ                                      |
| ------------------------------- | ---------------------------------------- |
| ! 1.1.1.1                       | हर IP पता लेकिन 1.1.1.1                  |
| !\[1.1.1.1, 1.1.1.2]            | हर IP पता लेकिन 1.1.1.1 और 1.1.1.2      |
| $HOME\_NET                     | yaml में आपके HOME\_NET का सेटिंग      |
| \[$EXTERNAL\_NET, !$HOME\_NET] | EXTERNAL\_NET और HOME\_NET नहीं         |
| \[10.0.0.0/24, !10.0.0.5]       | 10.0.0.0/24 सिवाय 10.0.0.5 के           |

#### स्रोत और गंतव्य पोर्ट

यह पोर्ट रेंज, नकारात्मकता और पोर्ट की सूचियों का समर्थन करता है

| उदाहरण          | अर्थ                                    |
| ---------------- | -------------------------------------- |
| any              | कोई भी पता                             |
| \[80, 81, 82]    | पोर्ट 80, 81 और 82                     |
| \[80: 82]        | 80 से 82 तक की रेंज                   |
| \[1024: ]        | 1024 से सबसे उच्च पोर्ट संख्या तक     |
| !80              | हर पोर्ट लेकिन 80                     |
| \[80:100,!99]    | 80 से 100 तक की रेंज लेकिन 99 को छोड़कर |
| \[1:80,!\[2,4]]  | 1-80 की रेंज, पोर्ट 2 और 4 को छोड़कर  |

#### दिशा

यह संचार नियम की दिशा को इंगित करना संभव है:
```
source -> destination
source <> destination  (both directions)
```
#### Keywords

Suricata में **विशिष्ट पैकेट** के लिए खोजने के लिए **सैकड़ों विकल्प** उपलब्ध हैं, यहाँ उल्लेख किया जाएगा यदि कुछ दिलचस्प पाया जाता है। अधिक जानकारी के लिए [**दस्तावेज़ीकरण** ](https://suricata.readthedocs.io/en/suricata-6.0.0/rules/index.html) की जाँच करें!
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
सीखें और AWS हैकिंग का अभ्यास करें:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
सीखें और GCP हैकिंग का अभ्यास करें: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks का समर्थन करें</summary>

* [**सदस्यता योजनाएँ**](https://github.com/sponsors/carlospolop) देखें!
* **हमारे** 💬 [**Discord समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) में शामिल हों या **हमें** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** पर फॉलो करें।**
* **हैकिंग ट्रिक्स साझा करें और** [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) गिटहब रिपोजिटरी में PR सबमिट करें।

</details>
{% endhint %}
