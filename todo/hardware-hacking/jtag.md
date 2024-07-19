# JTAG

{% hint style="success" %}
AWS हैकिंग सीखें और अभ्यास करें:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP हैकिंग सीखें और अभ्यास करें: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks का समर्थन करें</summary>

* [**सदस्यता योजनाएँ**](https://github.com/sponsors/carlospolop) देखें!
* **💬 [**Discord समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) में शामिल हों या **Twitter** 🐦 पर हमें **फॉलो करें** [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **हैकिंग ट्रिक्स साझा करें और** [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) गिटहब रिपोजिटरी में PR सबमिट करें।

</details>
{% endhint %}

## JTAGenum

[**JTAGenum** ](https://github.com/cyphunk/JTAGenum) एक उपकरण है जिसका उपयोग एक Raspberry PI या Arduino के साथ एक अज्ञात चिप से JTAG पिन खोजने के लिए किया जा सकता है।\
**Arduino** में, **2 से 11 तक के पिन को 10 पिन से जोड़ें जो संभवतः JTAG से संबंधित हैं**। Arduino में प्रोग्राम लोड करें और यह सभी पिन को ब्रूटफोर्स करने की कोशिश करेगा कि क्या कोई पिन JTAG से संबंधित है और कौन सा है।\
**Raspberry PI** में आप केवल **1 से 6 तक के पिन** का उपयोग कर सकते हैं (6 पिन, इसलिए आप प्रत्येक संभावित JTAG पिन का परीक्षण करते समय धीमे जाएंगे)।

### Arduino

Arduino में, केबल कनेक्ट करने के बाद (पिन 2 से 11 को JTAG पिन और Arduino GND को बेसबोर्ड GND से जोड़ें), **Arduino में JTAGenum प्रोग्राम लोड करें** और सीरियल मॉनिटर में **`h`** (मदद के लिए कमांड) भेजें और आपको मदद देखनी चाहिए:

![](<../../.gitbook/assets/image (939).png>)

![](<../../.gitbook/assets/image (578).png>)

**"No line ending" और 115200baud** कॉन्फ़िगर करें।\
स्कैनिंग शुरू करने के लिए कमांड s भेजें:

![](<../../.gitbook/assets/image (774).png>)

यदि आप एक JTAG से संपर्क कर रहे हैं, तो आप एक या एक से अधिक **लाइन FOUND!** से शुरू होते हुए पाएंगे जो JTAG के पिन को इंगित करते हैं।

{% hint style="success" %}
AWS हैकिंग सीखें और अभ्यास करें:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP हैकिंग सीखें और अभ्यास करें: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks का समर्थन करें</summary>

* [**सदस्यता योजनाएँ**](https://github.com/sponsors/carlospolop) देखें!
* **💬 [**Discord समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) में शामिल हों या **Twitter** 🐦 पर हमें **फॉलो करें** [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **हैकिंग ट्रिक्स साझा करें और** [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) गिटहब रिपोजिटरी में PR सबमिट करें।

</details>
{% endhint %}
