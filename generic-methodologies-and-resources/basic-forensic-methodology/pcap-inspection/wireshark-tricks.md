# Wireshark tricks

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


## Improve your Wireshark skills

### Tutorials

निम्नलिखित ट्यूटोरियल कुछ शानदार बुनियादी ट्रिक्स सीखने के लिए अद्भुत हैं:

* [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
* [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
* [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
* [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### Analysed Information

**Expert Information**

_**Analyze** --> **Expert Information**_ पर क्लिक करने से आपको पैकेट्स में हो रही गतिविधियों का **अवलोकन** मिलेगा **विश्लेषित**:

![](<../../../.gitbook/assets/image (256).png>)

**Resolved Addresses**

_**Statistics --> Resolved Addresses**_ के तहत आप कई **जानकारी** पा सकते हैं जो wireshark द्वारा "**resolved**" की गई है जैसे पोर्ट/परिवहन से प्रोटोकॉल, MAC से निर्माता, आदि। यह जानना दिलचस्प है कि संचार में क्या शामिल है।

![](<../../../.gitbook/assets/image (893).png>)

**Protocol Hierarchy**

_**Statistics --> Protocol Hierarchy**_ के तहत आप संचार में शामिल **प्रोटोकॉल** और उनके बारे में डेटा पा सकते हैं।

![](<../../../.gitbook/assets/image (586).png>)

**Conversations**

_**Statistics --> Conversations**_ के तहत आप संचार में **संवादों का सारांश** और उनके बारे में डेटा पा सकते हैं।

![](<../../../.gitbook/assets/image (453).png>)

**Endpoints**

_**Statistics --> Endpoints**_ के तहत आप संचार में **एंडपॉइंट्स का सारांश** और उनके बारे में डेटा पा सकते हैं।

![](<../../../.gitbook/assets/image (896).png>)

**DNS info**

_**Statistics --> DNS**_ के तहत आप कैप्चर किए गए DNS अनुरोध के बारे में आंकड़े पा सकते हैं।

![](<../../../.gitbook/assets/image (1063).png>)

**I/O Graph**

_**Statistics --> I/O Graph**_ के तहत आप संचार का **ग्राफ** पा सकते हैं।

![](<../../../.gitbook/assets/image (992).png>)

### Filters

यहां आप प्रोटोकॉल के आधार पर wireshark फ़िल्टर पा सकते हैं: [https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
अन्य दिलचस्प फ़िल्टर:

* `(http.request or ssl.handshake.type == 1) and !(udp.port eq 1900)`
* HTTP और प्रारंभिक HTTPS ट्रैफ़िक
* `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
* HTTP और प्रारंभिक HTTPS ट्रैफ़िक + TCP SYN
* `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
* HTTP और प्रारंभिक HTTPS ट्रैफ़िक + TCP SYN + DNS अनुरोध

### Search

यदि आप सत्रों के **पैकेट्स** के अंदर **सामग्री** के लिए **खोज** करना चाहते हैं तो _CTRL+f_ दबाएं। आप मुख्य जानकारी बार (No., Time, Source, आदि) में नए लेयर जोड़ सकते हैं, दाएं बटन को दबाकर और फिर कॉलम संपादित करके।

### Free pcap labs

**मुफ्त चुनौतियों के साथ अभ्यास करें:** [**https://www.malware-traffic-analysis.net/**](https://www.malware-traffic-analysis.net)

## Identifying Domains

आप एक कॉलम जोड़ सकते हैं जो Host HTTP हेडर दिखाता है:

![](<../../../.gitbook/assets/image (639).png>)

और एक कॉलम जो एक प्रारंभिक HTTPS कनेक्शन से सर्वर नाम जोड़ता है (**ssl.handshake.type == 1**):

![](<../../../.gitbook/assets/image (408) (1).png>)

## Identifying local hostnames

### From DHCP

वर्तमान Wireshark में `bootp` के बजाय आपको `DHCP` के लिए खोज करनी होगी

![](<../../../.gitbook/assets/image (1013).png>)

### From NBNS

![](<../../../.gitbook/assets/image (1003).png>)

## Decrypting TLS

### Decrypting https traffic with server private key

_edit>preference>protocol>ssl>_

![](<../../../.gitbook/assets/image (1103).png>)

_संपादित करें_ और सर्वर और निजी कुंजी (_IP, Port, Protocol, Key file और password_) का सभी डेटा जोड़ें।

### Decrypting https traffic with symmetric session keys

Firefox और Chrome दोनों में TLS सत्र कुंजी लॉग करने की क्षमता होती है, जिसका उपयोग Wireshark के साथ TLS ट्रैफ़िक को डिक्रिप्ट करने के लिए किया जा सकता है। यह सुरक्षित संचार का गहन विश्लेषण करने की अनुमति देता है। इस डिक्रिप्शन को कैसे करना है, इस पर अधिक जानकारी [Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/) में एक गाइड में मिल सकती है।

इसका पता लगाने के लिए वातावरण के अंदर `SSLKEYLOGFILE` वेरिएबल के लिए खोजें।

साझा कुंजियों की एक फ़ाइल इस तरह दिखेगी:

![](<../../../.gitbook/assets/image (820).png>)

इसे wireshark में आयात करने के लिए _edit > preference > protocol > ssl > और इसे (Pre)-Master-Secret लॉग फ़ाइल नाम में आयात करें:

![](<../../../.gitbook/assets/image (989).png>)

## ADB communication

ADB संचार से एक APK निकालें जहां APK भेजा गया था:
```python
from scapy.all import *

pcap = rdpcap("final2.pcapng")

def rm_data(data):
splitted = data.split(b"DATA")
if len(splitted) == 1:
return data
else:
return splitted[0]+splitted[1][4:]

all_bytes = b""
for pkt in pcap:
if Raw in pkt:
a = pkt[Raw]
if b"WRTE" == bytes(a)[:4]:
all_bytes += rm_data(bytes(a)[24:])
else:
all_bytes += rm_data(bytes(a))
print(all_bytes)

f = open('all_bytes.data', 'w+b')
f.write(all_bytes)
f.close()
```
{% hint style="success" %}
सीखें और AWS हैकिंग का अभ्यास करें:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
सीखें और GCP हैकिंग का अभ्यास करें: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks का समर्थन करें</summary>

* [**सदस्यता योजनाएँ**](https://github.com/sponsors/carlospolop) देखें!
* **हमारे** 💬 [**Discord समूह**](https://discord.gg/hRep4RUj7f) या [**telegram समूह**](https://t.me/peass) में शामिल हों या **हमारा अनुसरण करें** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **हैकिंग ट्रिक्स साझा करें और** [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github रिपोजिटरी में PRs सबमिट करें।

</details>
{% endhint %}
