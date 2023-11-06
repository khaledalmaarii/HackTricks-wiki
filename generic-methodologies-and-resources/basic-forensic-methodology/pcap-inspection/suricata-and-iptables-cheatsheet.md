# Suricata और Iptables चीटशीट

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* क्या आप एक **साइबर सुरक्षा कंपनी** में काम करते हैं? क्या आप अपनी **कंपनी को HackTricks में विज्ञापित** देखना चाहते हैं? या क्या आपको **PEASS के नवीनतम संस्करण या HackTricks को PDF में डाउनलोड करने का उपयोग** करना चाहिए? [**सदस्यता योजनाएं**](https://github.com/sponsors/carlospolop) की जांच करें!
* खोजें [**The PEASS Family**](https://opensea.io/collection/the-peass-family), हमारा विशेष संग्रह [**NFTs**](https://opensea.io/collection/the-peass-family)
* प्राप्त करें [**आधिकारिक PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **शामिल हों** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) या **फॉलो** करें मुझे **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **अपने हैकिंग ट्रिक्स साझा करें, [hacktricks रेपो](https://github.com/carlospolop/hacktricks) और [hacktricks-cloud रेपो](https://github.com/carlospolop/hacktricks-cloud)** को PR जमा करके।

</details>

## Iptables

### चेन

Iptables चेन सिर्फ नियमों की सूचियाँ होती हैं, जो क्रम में प्रसंस्कृत होती हैं। आप हमेशा निम्नलिखित 3 चेन खोजेंगे, लेकिन अन्य चेन जैसे NAT भी समर्थित हो सकते हैं।

* **Input** - यह चेन आउटगोइंग कनेक्शन के व्यवहार को नियंत्रित करने के लिए उपयोग किया जाता है।
* **Forward** - यह चेन उन आउटगोइंग कनेक्शनों के लिए उपयोग किया जाता है जो स्थानीय रूप से डिलीवर नहीं किए जा रहे हैं। एक राउटर की तरह सोचें - डेटा हमेशा इसे भेजा जाता है लेकिन वास्तव में राउटर के लिए नहीं होता है; डेटा केवल अपने लक्ष्य की ओर फॉरवर्ड किया जाता है। यदि आप अपने सिस्टम पर किसी भी प्रकार का रूटिंग, NATing या कुछ और कर रहे हैं जो फॉरवर्डिंग की आवश्यकता होती है, तो आप इस चेन का उपयोग नहीं करेंगे।
* **Output** - यह चेन आउटगोइंग कनेक्शनों के लिए उपयोग किया जाता है।
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

### स्थापित करें और कॉन्फ़िगर करें

```bash
# Install Suricata
sudo apt-get install suricata

# Configure Suricata
sudo nano /etc/suricata/suricata.yaml
```

## Iptables

### Install & Config

```bash
# Install iptables
sudo apt-get install iptables

# Configure iptables
sudo nano /etc/iptables/rules.v4
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
### नियम परिभाषाएं

एक नियम/हस्ताक्षर निम्नलिखित से मिलकर बनता है:

* **कार्रवाई**, हस्ताक्षर मेल खाने पर क्या होगा यह निर्धारित करता है।
* **हेडर**, नियम का प्रोटोकॉल, आईपी पते, पोर्ट और दिशा को परिभाषित करता है।
* **नियम विकल्प**, नियम की विशेषताएं परिभाषित करती हैं।

![](<../../../.gitbook/assets/image (642) (3).png>)

#### **मान्य कार्रवाई हैं**

* चेतावनी - चेतावनी उत्पन्न करें
* पास - पैकेट की आगे की जांच रोकें
* **ड्रॉप** - पैकेट को छोड़ें और चेतावनी उत्पन्न करें
* **रिजेक्ट** - मेल खाने वाले पैकेट के प्रेषक को RST/ICMP अपरिपठ्य त्रुटि भेजें।
* rejectsrc - बस _reject_ के बराबर
* rejectdst - मेल खाने वाले पैकेट के प्राप्तकर्ता को RST/ICMP त्रुटि पैकेट भेजें।
* rejectboth - बातचीत के दोनों पक्षों को RST/ICMP त्रुटि पैकेट भेजें।

#### **प्रोटोकॉल**

* tcp (tcp-ट्रैफिक के लिए)
* udp
* icmp
* ip (ip 'सब' या 'कोई' के लिए होता है)
* _लेयर 7 प्रोटोकॉल_: http, ftp, tls, smb, dns, ssh... (अधिक जानकारी [**यहाँ**](https://suricata.readthedocs.io/en/suricata-6.0.0/rules/intro.html))

#### स्रोत और गंतव्य पते

इसमें आईपी सीमाएं, नकारात्मकता और पतों की सूची का समर्थन किया जाता है:

| उदाहरण                        | अर्थ                                  |
| ------------------------------ | ---------------------------------------- |
| ! 1.1.1.1                      | 1.1.1.1 को छोड़कर हर आईपी पता             |
| !\[1.1.1.1, 1.1.1.2]           | 1.1.1.1 और 1.1.1.2 को छोड़कर हर आईपी पता |
| $HOME\_NET                     | आपकी yaml में HOME\_NET की सेटिंग        |
| \[$EXTERNAL\_NET, !$HOME\_NET] | EXTERNAL\_NET और HOME\_NET नहीं           |
| \[10.0.0.0/24, !10.0.0.5]      | 10.0.0.0/24 को छोड़कर 10.0.0.5 के लिए नहीं |

#### स्रोत और गंतव्य पोर्ट

यह पोर्ट सीमाएं, नकारात्मकता और पोर्टों की सूची का समर्थन करता है

| उदाहरण         | अर्थ                                |
| --------------- | -------------------------------------- |
| any             | कोई भी पता                            |
| \[80, 81, 82]   | पोर्ट 80, 81 और 82                     |
| \[80: 82]       | 80 से 82 तक का सीमा                  |
| \[1024: ]       | 1024 से सबसे ऊचा पोर्ट-नंबर तक       |
| !80             | 80 को छोड़कर हर पोर्ट                  |
| \[80:100,!99]   | 80 से 100 तक का सीमा, लेकिन 99 छोड़ा |
| \[1:80,!\[2,4]] | 1-80 तक का सीमा, पोर्ट 2 और 4 को छोड़कर |

#### दिशा

संचार नियम की लागू होने वाली दिशा को निर्दिष्ट करना संभव है:
```
source -> destination
source <> destination  (both directions)
```
#### कीवर्ड

Suricata में **हजारों विकल्प** उपलब्ध हैं जिनका उपयोग करके आप खोज सकते हैं विशेष पैकेट के लिए, यदि कुछ दिलचस्प मिलता है तो यहां उल्लेख किया जाएगा। अधिक जानकारी के लिए [**दस्तावेज़ीकरण**](https://suricata.readthedocs.io/en/suricata-6.0.0/rules/index.html) देखें!
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

* क्या आप किसी **साइबर सुरक्षा कंपनी** में काम करते हैं? क्या आप अपनी **कंपनी को HackTricks में विज्ञापित करना चाहते हैं**? या क्या आपको **PEASS के नवीनतम संस्करण या HackTricks को PDF में डाउनलोड करने का उपयोग** करना है? [**सदस्यता योजनाएं**](https://github.com/sponsors/carlospolop) की जांच करें!
* खोजें [**The PEASS Family**](https://opensea.io/collection/the-peass-family), हमारा विशेष संग्रह [**NFTs**](https://opensea.io/collection/the-peass-family)
* प्राप्त करें [**आधिकारिक PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **शामिल हों** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) में **या** मुझे **Twitter** पर **फ़ॉलो** करें [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **अपने हैकिंग ट्रिक्स साझा करें, [hacktricks रेपो](https://github.com/carlospolop/hacktricks) और [hacktricks-cloud रेपो](https://github.com/carlospolop/hacktricks-cloud)** को PR जमा करके।

</details>
