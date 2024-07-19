# बेसिक फॉरेंसिक मेथोडोलॉजी

{% hint style="success" %}
AWS हैकिंग सीखें और अभ्यास करें:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP हैकिंग सीखें और अभ्यास करें: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks का समर्थन करें</summary>

* [**सदस्यता योजनाएँ**](https://github.com/sponsors/carlospolop) देखें!
* **हमारे साथ जुड़ें** 💬 [**Discord समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) या **हमें** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** पर फॉलो करें।**
* **हैकिंग ट्रिक्स साझा करें और** [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) गिटहब रिपोजिटरी में PR सबमिट करें।

</details>
{% endhint %}

## इमेज बनाना और माउंट करना

{% content-ref url="../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md" %}
[image-acquisition-and-mount.md](../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md)
{% endcontent-ref %}

## मैलवेयर विश्लेषण

यह **छवि प्राप्त करने के बाद करने के लिए पहला कदम जरूरी नहीं है**। लेकिन आप इस मैलवेयर विश्लेषण तकनीकों का स्वतंत्र रूप से उपयोग कर सकते हैं यदि आपके पास एक फ़ाइल, फ़ाइल-प्रणाली छवि, मेमोरी छवि, pcap... है, इसलिए यह **इन क्रियाओं को ध्यान में रखना अच्छा है**:

{% content-ref url="malware-analysis.md" %}
[malware-analysis.md](malware-analysis.md)
{% endcontent-ref %}

## इमेज का निरीक्षण करना

यदि आपको एक **फॉरेंसिक इमेज** दी गई है, तो आप **पार्टीशनों, फ़ाइल-प्रणाली** का विश्लेषण करना शुरू कर सकते हैं और **संभावित रूप से** **दिलचस्प फ़ाइलों** (यहां तक कि हटाई गई फ़ाइलों) को **पुनर्प्राप्त** कर सकते हैं। जानें कैसे:

{% content-ref url="partitions-file-systems-carving/" %}
[partitions-file-systems-carving](partitions-file-systems-carving/)
{% endcontent-ref %}

उपयोग किए गए OS और यहां तक कि प्लेटफार्म के आधार पर विभिन्न दिलचस्प कलाकृतियों की खोज की जानी चाहिए:

{% content-ref url="windows-forensics/" %}
[windows-forensics](windows-forensics/)
{% endcontent-ref %}

{% content-ref url="linux-forensics.md" %}
[linux-forensics.md](linux-forensics.md)
{% endcontent-ref %}

{% content-ref url="docker-forensics.md" %}
[docker-forensics.md](docker-forensics.md)
{% endcontent-ref %}

## विशिष्ट फ़ाइल-प्रकारों और सॉफ़्टवेयर की गहरी जांच

यदि आपके पास बहुत **संदिग्ध** **फ़ाइल** है, तो **फ़ाइल-प्रकार और सॉफ़्टवेयर** के आधार पर जो इसे बनाया है, कई **ट्रिक्स** उपयोगी हो सकते हैं।\
कुछ दिलचस्प ट्रिक्स जानने के लिए निम्नलिखित पृष्ठ पढ़ें:

{% content-ref url="specific-software-file-type-tricks/" %}
[specific-software-file-type-tricks](specific-software-file-type-tricks/)
{% endcontent-ref %}

मैं पृष्ठ का विशेष उल्लेख करना चाहता हूँ:

{% content-ref url="specific-software-file-type-tricks/browser-artifacts.md" %}
[browser-artifacts.md](specific-software-file-type-tricks/browser-artifacts.md)
{% endcontent-ref %}

## मेमोरी डंप निरीक्षण

{% content-ref url="memory-dump-analysis/" %}
[memory-dump-analysis](memory-dump-analysis/)
{% endcontent-ref %}

## Pcap निरीक्षण

{% content-ref url="pcap-inspection/" %}
[pcap-inspection](pcap-inspection/)
{% endcontent-ref %}

## **एंटी-फॉरेंसिक तकनीकें**

एंटी-फॉरेंसिक तकनीकों के संभावित उपयोग को ध्यान में रखें:

{% content-ref url="anti-forensic-techniques.md" %}
[anti-forensic-techniques.md](anti-forensic-techniques.md)
{% endcontent-ref %}

## खतरे की खोज

{% content-ref url="file-integrity-monitoring.md" %}
[file-integrity-monitoring.md](file-integrity-monitoring.md)
{% endcontent-ref %}

{% hint style="success" %}
AWS हैकिंग सीखें और अभ्यास करें:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP हैकिंग सीखें और अभ्यास करें: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks का समर्थन करें</summary>

* [**सदस्यता योजनाएँ**](https://github.com/sponsors/carlospolop) देखें!
* **हमारे साथ जुड़ें** 💬 [**Discord समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) या **हमें** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** पर फॉलो करें।**
* **हैकिंग ट्रिक्स साझा करें और** [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) गिटहब रिपोजिटरी में PR सबमिट करें।

</details>
{% endhint %}
