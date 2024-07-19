{% hint style="success" %}
AWS हैकिंग सीखें और अभ्यास करें:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP हैकिंग सीखें और अभ्यास करें: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks का समर्थन करें</summary>

* [**सदस्यता योजनाएँ**](https://github.com/sponsors/carlospolop) देखें!
* **हमारे** 💬 [**Discord समूह**](https://discord.gg/hRep4RUj7f) या [**telegram समूह**](https://t.me/peass) में शामिल हों या **हमारा अनुसरण करें** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **हैकिंग ट्रिक्स साझा करें,** [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) गिटहब रिपोजिटरी में PR सबमिट करके।

</details>
{% endhint %}


एक पिंग प्रतिक्रिया TTL में:\
127 = Windows\
254 = Cisco\
बाकी, कुछ linux

$1$- md5\
$2$या $2a$ - Blowfish\
$5$- sha256\
$6$- sha512

यदि आप नहीं जानते कि किसी सेवा के पीछे क्या है, तो एक HTTP GET अनुरोध करने का प्रयास करें।

**UDP स्कैन**\
nc -nv -u -z -w 1 \<IP> 160-16

एक खाली UDP पैकेट एक विशिष्ट पोर्ट पर भेजा जाता है। यदि UDP पोर्ट खुला है, तो लक्ष्य मशीन से कोई उत्तर वापस नहीं भेजा जाता है। यदि UDP पोर्ट बंद है, तो लक्ष्य मशीन से एक ICMP पोर्ट अप्राप्य पैकेट वापस भेजा जाना चाहिए।\

UDP पोर्ट स्कैनिंग अक्सर अविश्वसनीय होती है, क्योंकि फ़ायरवॉल और राउटर ICMP\
पैकेट को गिरा सकते हैं। इससे आपके स्कैन में झूठे सकारात्मक परिणाम हो सकते हैं, और आप नियमित रूप से देखेंगे\
UDP पोर्ट स्कैनिंग में सभी UDP पोर्ट खुले दिखाए जाते हैं।\
अधिकांश पोर्ट स्कैनर सभी उपलब्ध पोर्ट को स्कैन नहीं करते हैं, और आमतौर पर एक पूर्व निर्धारित सूची होती है\
“दिलचस्प पोर्ट” की जो स्कैन की जाती है।

# CTF - ट्रिक्स

**Windows** में फ़ाइलों की खोज के लिए **Winzip** का उपयोग करें।\
**वैकल्पिक डेटा स्ट्रीम**: _dir /r | find ":$DATA"_\
```
binwalk --dd=".*" <file> #Extract everything
binwalk -M -e -d=10000 suspicious.pdf #Extract, look inside extracted files and continue extracing (depth of 10000)
```
## Crypto

**featherduster**\


**Basae64**(6—>8) —> 0...9, a...z, A…Z,+,/\
**Base32**(5 —>8) —> A…Z, 2…7\
**Base85** (Ascii85, 7—>8) —> 0...9, a...z, A...Z, ., -, :, +, =, ^, !, /, \*, ?, &, <, >, (, ), \[, ], {, }, @, %, $, #\
**Uuencode** --> "_begin \<mode> \<filename>_" से शुरू करें और अजीब अक्षर\
**Xxencoding** --> "_begin \<mode> \<filename>_" से शुरू करें और B64\
\
**Vigenere** (frequency analysis) —> [https://www.guballa.de/vigenere-solver](https://www.guballa.de/vigenere-solver)\
**Scytale** (offset of characters) —> [https://www.dcode.fr/scytale-cipher](https://www.dcode.fr/scytale-cipher)

**25x25 = QR**

factordb.com\
rsatool

Snow --> स्पेस और टैब का उपयोग करके संदेश छिपाएं

# Characters

%E2%80%AE => RTL Character (payloads को उल्टा लिखता है)


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
