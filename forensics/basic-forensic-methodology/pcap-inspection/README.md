# Pcap Inspection

{% hint style="success" %}
सीखें और प्रैक्टिस करें AWS हैकिंग:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks प्रशिक्षण AWS रेड टीम एक्सपर्ट (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
सीखें और प्रैक्टिस करें GCP हैकिंग: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks प्रशिक्षण GCP रेड टीम एक्सपर्ट (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>हैकट्रिक्स का समर्थन करें</summary>

* [**सदस्यता योजनाएं**](https://github.com/sponsors/carlospolop) की जाँच करें!
* **शामिल हों** 💬 [**डिस्कॉर्ड समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) या हमें **ट्विटर** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** पर फॉलो** करें।
* **हैकिंग ट्रिक्स साझा करें, हैकट्रिक्स**](https://github.com/carlospolop/hacktricks) **और हैकट्रिक्स क्लाउड**](https://github.com/carlospolop/hacktricks-cloud) **github रेपो में PR जमा करके।

</details>
{% endhint %}

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) **स्पेन** में सबसे महत्वपूर्ण साइबर सुरक्षा घटना है और यूरोप में सबसे महत्वपूर्ण में से एक है। **तकनीकी ज्ञान को बढ़ावा देने** के मिशन के साथ, यह कांग्रेस प्रौद्योगिकी और साइबर सुरक्षा विशेषज्ञों के लिए एक उबाऊ मिलन स्थल है।

{% embed url="https://www.rootedcon.com/" %}

{% hint style="info" %}
**PCAP** vs **PCAPNG** के बारे में एक नोट: PCAP फ़ाइल प्रारूप के दो संस्करण हैं; **PCAPNG नया है और सभी उपकरणों द्वारा समर्थित नहीं है**। कुछ अन्य उपकरणों में इसके साथ काम करने के लिए आपको एक फ़ाइल को PCAP से PCAPNG में रूपांतरित करने की आवश्यकता हो सकती है, Wireshark या किसी अन्य संगत उपकरण का उपयोग करके।
{% endhint %}

## Pcap के लिए ऑनलाइन उपकरण

* यदि आपके pcap का हेडर **टूटा** हुआ है तो आपको इसे ठीक करने की कोशिश करनी चाहिए: [http://f00l.de/hacking/**pcapfix.php**](http://f00l.de/hacking/pcapfix.php)
* [**PacketTotal**](https://packettotal.com) में pcap में **जानकारी** निकालें और **मैलवेयर** खोजें
* [**www.virustotal.com**](https://www.virustotal.com) और [**www.hybrid-analysis.com**](https://www.hybrid-analysis.com) का उपयोग करके **दुष्ट गतिविधि** खोजें

## जानकारी निकालें

निम्नलिखित उपकरण सांख्यिकी, फ़ाइलें आदि निकालने के लिए उपयोगी हैं।

### Wireshark

{% hint style="info" %}
**यदि आप PCAP का विश्लेषण करने जा रहे हैं तो आपको बुनियादी रूप से Wireshark का उपयोग कैसे करना है, इसे जानना चाहिए**
{% endhint %}

आप Wireshark में कुछ ट्रिक्स यहाँ पा सकते हैं:

{% content-ref url="wireshark-tricks.md" %}
[wireshark-tricks.md](wireshark-tricks.md)
{% endcontent-ref %}

### Xplico Framework

[**Xplico** ](https://github.com/xplico/xplico)_(केवल लिनक्स)_ एक **pcap** का विश्लेषण कर सकता है और इससे जानकारी निकाल सकता है। उदाहरण के लिए, एक pcap फ़ाइल से Xplico, प्रत्येक ईमेल (POP, IMAP, और SMTP प्रोटोकॉल), सभी HTTP सामग्री, प्रत्येक VoIP कॉल (SIP), FTP, TFTP, और इत्यादि निकालता है।

**स्थापित करें**
```bash
sudo bash -c 'echo "deb http://repo.xplico.org/ $(lsb_release -s -c) main" /etc/apt/sources.list'
sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 791C25CE
sudo apt-get update
sudo apt-get install xplico
```
**चलाएं**
```
/etc/init.d/apache2 restart
/etc/init.d/xplico start
```
_**127.0.0.1:9876**_ क्रेडेंशियल के साथ पहुंचें _**xplico:xplico**_

फिर **नया मामला** बनाएं, मामले के अंदर **नई सत्र** बनाएं और **pcap फ़ाइल अपलोड** करें।

### NetworkMiner

Xplico की तरह यह एक उपकरण है **pcaps से वस्तुओं का विश्लेषण और निकालने** के लिए। इसका एक मुफ्त संस्करण है जिसे आप [**यहाँ**](https://www.netresec.com/?page=NetworkMiner) से **डाउनलोड** कर सकते हैं। यह **Windows** के साथ काम करता है।\
यह उपकरण भी **पैकेट्स से अन्य जानकारी** प्राप्त करने के लिए उपयोगी है ताकि आप एक **तेज़ तरीके से** क्या हो रहा था उसे जान सकें।

### NetWitness Investigator

आप [**यहाँ से NetWitness Investigator डाउनलोड कर सकते हैं**](https://www.rsa.com/en-us/contact-us/netwitness-investigator-freeware) **(यह Windows में काम करता है)**।\
यह एक और उपयोगी उपकरण है जो **पैकेट्स का विश्लेषण** करता है और जानकारी को एक उपयोगी तरीके से **व्यवस्थित करता है** ताकि आप यह जान सकें कि अंदर क्या हो रहा है।

### [BruteShark](https://github.com/odedshimon/BruteShark)

* उपयोगकर्ता नाम और पासवर्ड को निकालना और एन्कोड करना (HTTP, FTP, Telnet, IMAP, SMTP...)
* प्रमाणीकरण हैश निकालना और Hashcat का उपयोग करके उन्हें क्रैक करना (Kerberos, NTLM, CRAM-MD5, HTTP-Digest...)
* एक विजुअल नेटवर्क आरेखित करना (नेटवर्क नोड्स और उपयोगकर्ता)
* DNS क्वेरी निकालना
* सभी TCP और UDP सत्र पुनर्निर्माण करना
* फ़ाइल कार्विंग

### Capinfos
```
capinfos capture.pcap
```
### Ngrep

यदि आप pcap के अंदर कुछ **खोज** रहे हैं तो आप **ngrep** का उपयोग कर सकते हैं। यहाँ मुख्य फ़िल्टर्स का उपयोग करके एक उदाहरण है:
```bash
ngrep -I packets.pcap "^GET" "port 80 and tcp and host 192.168 and dst host 192.168 and src host 192.168"
```
### Carving

सामान्य कार्विंग तकनीक का उपयोग करके pcap से फ़ाइलें और जानकारी निकालना उपयोगी हो सकता है:

{% content-ref url="../partitions-file-systems-carving/file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](../partitions-file-systems-carving/file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### क्रेडेंशियल कैप्चरिंग

आप [https://github.com/lgandx/PCredz](https://github.com/lgandx/PCredz) जैसे उपकरणों का उपयोग कर सकते हैं ताकि आप pcap या लाइव इंटरफेस से क्रेडेंशियल को पार्स कर सकें।

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) **स्पेन** में सबसे महत्वपूर्ण साइबर सुरक्षा घटना है और **यूरोप** में सबसे महत्वपूर्ण में से एक है। **तकनीकी ज्ञान को बढ़ावा देने** के मिशन के साथ, यह कांग्रेस प्रौद्योगिकी और साइबर सुरक्षा विशेषज्ञों के लिए एक उबाऊ मिलन स्थल है।

{% embed url="https://www.rootedcon.com/" %}

## जांच एक्सप्लॉइट्स/मैलवेयर

### Suricata

**स्थापित करें और सेटअप**
```
apt-get install suricata
apt-get install oinkmaster
echo "url = http://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz" >> /etc/oinkmaster.conf
oinkmaster -C /etc/oinkmaster.conf -o /etc/suricata/rules
```
**पीकैप जाँचें**
```
suricata -r packets.pcap -c /etc/suricata/suricata.yaml -k none -v -l log
```
### यारापीसीएपी

[**YaraPCAP**](https://github.com/kevthehermit/YaraPcap) एक टूल है जो

* एक PCAP फ़ाइल पढ़ता है और Http स्ट्रीम निकालता है।
* किसी भी संपीड़ित स्ट्रीम को gzip डिफ़्लेट करता है
* हर फ़ाइल को यारा के साथ स्कैन करता है
* रिपोर्ट.txt लिखता है
* वैकल्पिक रूप से मिलने वाली फ़ाइलों को एक डिर में सहेजता है

### मैलवेयर विश्लेषण

जांच करें कि क्या आप किसी जाने-माने मैलवेयर का कोई आंकड़ा खोज सकते हैं:

{% content-ref url="../malware-analysis.md" %}
[malware-analysis.md](../malware-analysis.md)
{% endcontent-ref %}

## Zeek

> [Zeek](https://docs.zeek.org/en/master/about.html) एक पैसिव, ओपन-सोर्स नेटवर्क ट्रैफ़िक विश्लेषक है। कई ऑपरेटर संदेहपूर्ण या दुष्ट गतिविधि की जांच का समर्थन करने के लिए Zeek का उपयोग नेटवर्क सुरक्षा मॉनिटर (NSM) के रूप में करते हैं। Zeek नेटवर्क सुरक्षा डोमेन के अलावा एक व्यापक ट्रैफ़िक विश्लेषण कार्यों का समर्थन भी करता है, जिसमें प्रदर्शन मापन और ट्रबलशूटिंग शामिल है।

मूल रूप से, `zeek` द्वारा बनाए गए लॉग **पीकैप्स** नहीं हैं। इसलिए आपको लॉग विश्लेषित करने के लिए **अन्य उपकरण** का उपयोग करना होगा जहां **पीकैप्स** के बारे में **जानकारी** हो।

### कनेक्शन जानकारी
```bash
#Get info about longest connections (add "grep udp" to see only udp traffic)
#The longest connection might be of malware (constant reverse shell?)
cat conn.log | zeek-cut id.orig_h id.orig_p id.resp_h id.resp_p proto service duration | sort -nrk 7 | head -n 10

10.55.100.100   49778   65.52.108.225   443     tcp     -       86222.365445
10.55.100.107   56099   111.221.29.113  443     tcp     -       86220.126151
10.55.100.110   60168   40.77.229.82    443     tcp     -       86160.119664


#Improve the metrics by summing up the total duration time for connections that have the same destination IP and Port.
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p proto duration | awk 'BEGIN{ FS="\t" } { arr[$1 FS $2 FS $3 FS $4] += $5 } END{ for (key in arr) printf "%s%s%s\n", key, FS, arr[key] }' | sort -nrk 5 | head -n 10

10.55.100.100   65.52.108.225   443     tcp     86222.4
10.55.100.107   111.221.29.113  443     tcp     86220.1
10.55.100.110   40.77.229.82    443     tcp     86160.1

#Get the number of connections summed up per each line
cat conn.log | zeek-cut id.orig_h id.resp_h duration | awk 'BEGIN{ FS="\t" } { arr[$1 FS $2] += $3; count[$1 FS $2] += 1 } END{ for (key in arr) printf "%s%s%s%s%s\n", key, FS, count[key], FS, arr[key] }' | sort -nrk 4 | head -n 10

10.55.100.100   65.52.108.225   1       86222.4
10.55.100.107   111.221.29.113  1       86220.1
10.55.100.110   40.77.229.82    134       86160.1

#Check if any IP is connecting to 1.1.1.1
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p proto service | grep '1.1.1.1' | sort | uniq -c

#Get number of connections per source IP, dest IP and dest Port
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p proto | awk 'BEGIN{ FS="\t" } { arr[$1 FS $2 FS $3 FS $4] += 1 } END{ for (key in arr) printf "%s%s%s\n", key, FS, arr[key] }' | sort -nrk 5 | head -n 10


# RITA
#Something similar can be done with the tool rita
rita show-long-connections -H --limit 10 zeek_logs

+---------------+----------------+--------------------------+----------------+
|   SOURCE IP   | DESTINATION IP | DSTPORT:PROTOCOL:SERVICE |    DURATION    |
+---------------+----------------+--------------------------+----------------+
| 10.55.100.100 | 65.52.108.225  | 443:tcp:-                | 23h57m2.3655s  |
| 10.55.100.107 | 111.221.29.113 | 443:tcp:-                | 23h57m0.1262s  |
| 10.55.100.110 | 40.77.229.82   | 443:tcp:-                | 23h56m0.1197s  |

#Get connections info from rita
rita show-beacons zeek_logs | head -n 10
Score,Source IP,Destination IP,Connections,Avg Bytes,Intvl Range,Size Range,Top Intvl,Top Size,Top Intvl Count,Top Size Count,Intvl Skew,Size Skew,Intvl Dispersion,Size Dispersion
1,192.168.88.2,165.227.88.15,108858,197,860,182,1,89,53341,108319,0,0,0,0
1,10.55.100.111,165.227.216.194,20054,92,29,52,1,52,7774,20053,0,0,0,0
0.838,10.55.200.10,205.251.194.64,210,69,29398,4,300,70,109,205,0,0,0,0
```
### DNS जानकारी
```bash
#Get info about each DNS request performed
cat dns.log | zeek-cut -c id.orig_h query qtype_name answers

#Get the number of times each domain was requested and get the top 10
cat dns.log | zeek-cut query | sort | uniq | rev | cut -d '.' -f 1-2 | rev | sort | uniq -c | sort -nr | head -n 10

#Get all the IPs
cat dns.log | zeek-cut id.orig_h query | grep 'example\.com' | cut -f 1 | sort | uniq -c

#Sort the most common DNS record request (should be A)
cat dns.log | zeek-cut qtype_name | sort | uniq -c | sort -nr

#See top DNS domain requested with rita
rita show-exploded-dns -H --limit 10 zeek_logs
```
## अन्य pcap विश्लेषण ट्रिक्स

{% content-ref url="dnscat-exfiltration.md" %}
[dnscat-exfiltration.md](dnscat-exfiltration.md)
{% endcontent-ref %}

{% content-ref url="wifi-pcap-analysis.md" %}
[wifi-pcap-analysis.md](wifi-pcap-analysis.md)
{% endcontent-ref %}

{% content-ref url="usb-keystrokes.md" %}
[usb-keystrokes.md](usb-keystrokes.md)
{% endcontent-ref %}

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) स्पेन में सबसे महत्वपूर्ण साइबर सुरक्षा घटना है और यूरोप में सबसे महत्वपूर्ण में से एक है। **तकनीकी ज्ञान को बढ़ावा देने** के मिशन के साथ, यह कांग्रेस प्रौद्योगिकी और साइबर सुरक्षा विशेषज्ञों के लिए एक उफान मिलने का समारोह है।

{% embed url="https://www.rootedcon.com/" %}

{% hint style="success" %}
AWS हैकिंग सीखें और अभ्यास करें:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP हैकिंग सीखें और अभ्यास करें: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>हैकट्रिक्स का समर्थन करें</summary>

* [**सदस्यता योजनाएं**](https://github.com/sponsors/carlospolop) की जाँच करें!
* **शामिल हों** 💬 [**डिस्कॉर्ड समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) और **ट्विटर** 🐦 पर हमें **फॉलो** करें [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **हैकिंग ट्रिक्स साझा करें** [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos में PR जमा करके।

</details>
{% endhint %}
