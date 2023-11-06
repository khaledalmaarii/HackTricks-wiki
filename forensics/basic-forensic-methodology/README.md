# मूल फोरेंसिक मेथडोलॉजी

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* क्या आप किसी **साइबर सुरक्षा कंपनी** में काम करते हैं? क्या आप अपनी **कंपनी को HackTricks में विज्ञापित** देखना चाहते हैं? या क्या आपको **PEASS के नवीनतम संस्करण या HackTricks को PDF में डाउनलोड करने का उपयोग** करने की आवश्यकता है? [**सदस्यता योजनाएं**](https://github.com/sponsors/carlospolop) की जांच करें!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) की खोज करें, हमारा विशेष संग्रह [**NFTs**](https://opensea.io/collection/the-peass-family)
* [**आधिकारिक PEASS & HackTricks swag**](https://peass.creator-spring.com) प्राप्त करें
* **शामिल हों** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) या **Twitter** पर **मेरा अनुसरण करें** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **हैकिंग ट्रिक्स को साझा करें** [hacktricks रेपो](https://github.com/carlospolop/hacktricks) और [hacktricks-cloud रेपो](https://github.com/carlospolop/hacktricks-cloud) में पीआर जमा करके।

</details>

## एक छवि बनाना और माउंट करना

{% content-ref url="../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md" %}
[image-acquisition-and-mount.md](../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md)
{% endcontent-ref %}

## मैलवेयर विश्लेषण

यह **छवि के पास होने के बाद करने के लिए आवश्यक नहीं है**। लेकिन आप इस मैलवेयर विश्लेषण तकनीक का अलग-थलग उपयोग कर सकते हैं अगर आपके पास एक फ़ाइल, फ़ाइल-सिस्टम छवि, मेमोरी छवि, पीकैप... है, तो यह अच्छा होगा कि **इन कार्रवाइयों को ध्यान में रखें**:

{% content-ref url="malware-analysis.md" %}
[malware-analysis.md](malware-analysis.md)
{% endcontent-ref %}

## छवि की जांच

यदि आपको एक उपकरण की **फोरेंसिक छवि** दी जाती है, तो आप **विभाजनों, फ़ाइल-सिस्टम** का उपयोग करके शुरू कर सकते हैं और पोटेंशियली **दिलचस्प फ़ाइलें** (हटाई गई भी) को **पुनर्प्राप्त कर सकते हैं**। इसे सीखें:

{% content-ref url="partitions-file-systems-carving/" %}
[partitions-file-systems-carving](partitions-file-systems-carving/)
{% endcontent-ref %}

उपयोग किए जाने वाले ओएस और प्लेटफ़ॉर्म के आधार पर विभिन्न दिलचस्प आर्टिफैक्ट्स खोजने चाहिए:

{% content-ref url="windows-forensics/" %}
[windows-forensics](windows-forensics/)
{% endcontent-ref %}

{% content-ref url="linux-forensics.md" %}
[linux-forensics.md](linux-forensics.md)
{% endcontent-ref %}

{% content-ref url="docker-forensics.md" %}
[docker-forensics.md](docker-forensics.md)
{% endcontent-ref %}

## विशेष फ़ाइल-प्रकार और सॉफ़्टवेयर की गहन जांच

यदि आपके पास बहुत **संदिग्ध फ़ाइल** है, तो **फ़ाइल-प्रकार और सॉफ़्टवेयर** पर निर्भर करता है कि कौन से **ट्रिक्स** उपयोगी हो सकते हैं।\
कुछ दिलचस्प ट्रिक्स सीखने के लिए निम्नलिखित पृष्ठ को पढ़ें:

{% content-ref url="specific-software-file-type-tricks/" %}
[specific-software-file-type-tricks](specific-software-file-type-tricks/)
{% endcontent-ref %}

मैं एक विशेष उल्लेख करना चाहता हूँ पृष्ठ का:

{% content-ref url="specific-software-file-type-tricks/browser-artifacts.md" %}
[browser-artifacts.md](specific-software-file-type-tricks/browser-artifacts.md)
{% endcontent-ref %}

## मेमोरी डंप जांच

{% content-ref url="memory-dump-analysis/" %}
[memory-dump-analysis](memory-dump-analysis/)
{% endcontent-ref %}

## Pcap जांच

{% content-ref url="pcap-inspection/" %}
[pcap-inspection](pcap-inspection/)
{% endcontent-ref %}

## **एंटी-फोरेंसिक तकनीकें**

एंटी-फोरेंसिक तकनीकों का उपयोग करने की संभावना को ध्यान में रखें:

{% content-ref url="anti-forensic-techniques.md" %}
[anti-forensic-techniques.md](anti-forensic-techniques.md)
{% endcontent-ref %}

## धमकी हंटिंग

{% content-ref url="file-integrity-monitoring.md" %}
[file-integrity-monitoring.md](file-integrity-monitoring.md)
{% end
