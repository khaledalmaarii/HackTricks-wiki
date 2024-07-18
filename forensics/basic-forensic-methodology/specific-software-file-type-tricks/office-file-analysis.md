# Office file analysis

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

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) to easily build and **automate workflows** powered by the world's **most advanced** community tools.\
Get Access Today:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

For further information check [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). This is just a sumary:

Microsoft ने कई ऑफिस दस्तावेज़ प्रारूप बनाए हैं, जिनमें दो मुख्य प्रकार **OLE प्रारूप** (जैसे RTF, DOC, XLS, PPT) और **Office Open XML (OOXML) प्रारूप** (जैसे DOCX, XLSX, PPTX) हैं। ये प्रारूप मैक्रोज़ शामिल कर सकते हैं, जिससे ये फ़िशिंग और मैलवेयर के लक्ष्यों बन जाते हैं। OOXML फ़ाइलें ज़िप कंटेनरों के रूप में संरचित होती हैं, जिन्हें अनज़िप करके निरीक्षण किया जा सकता है, जिससे फ़ाइल और फ़ोल्डर हायरार्की और XML फ़ाइल की सामग्री प्रकट होती है।

OOXML फ़ाइल संरचनाओं का अन्वेषण करने के लिए, एक दस्तावेज़ को अनज़िप करने के लिए कमांड और आउटपुट संरचना दी गई है। इन फ़ाइलों में डेटा छिपाने की तकनीकों का दस्तावेजीकरण किया गया है, जो CTF चुनौतियों के भीतर डेटा छिपाने में निरंतर नवाचार को दर्शाता है।

विश्लेषण के लिए, **oletools** और **OfficeDissector** OLE और OOXML दस्तावेज़ों की जांच के लिए व्यापक टूलसेट प्रदान करते हैं। ये उपकरण एम्बेडेड मैक्रोज़ की पहचान और विश्लेषण में मदद करते हैं, जो अक्सर मैलवेयर वितरण के लिए वेक्टर के रूप में कार्य करते हैं, आमतौर पर अतिरिक्त दुर्भावनापूर्ण पेलोड डाउनलोड और निष्पादित करते हैं। VBA मैक्रोज़ का विश्लेषण Microsoft Office के बिना Libre Office का उपयोग करके किया जा सकता है, जो ब्रेकपॉइंट और वॉच वेरिएबल के साथ डिबगिंग की अनुमति देता है।

**oletools** की स्थापना और उपयोग सरल है, दस्तावेज़ों से मैक्रोज़ निकालने के लिए pip के माध्यम से स्थापित करने के लिए कमांड प्रदान किए गए हैं। मैक्रोज़ का स्वचालित निष्पादन `AutoOpen`, `AutoExec`, या `Document_Open` जैसी कार्यों द्वारा ट्रिगर किया जाता है।
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) का उपयोग करें ताकि आप दुनिया के **सबसे उन्नत** सामुदायिक उपकरणों द्वारा संचालित **कार्यप्रवाहों** को आसानी से बना और **स्वचालित** कर सकें।\
आज ही एक्सेस प्राप्त करें:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

{% hint style="success" %}
AWS हैकिंग सीखें और अभ्यास करें:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP हैकिंग सीखें और अभ्यास करें: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks का समर्थन करें</summary>

* [**सदस्यता योजनाओं**](https://github.com/sponsors/carlospolop) की जांच करें!
* **हमारे** 💬 [**Discord समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) में शामिल हों या **हमें** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** पर फॉलो करें।**
* हैकिंग ट्रिक्स साझा करें और [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) गिटहब रिपोजिटरी में PR सबमिट करें।

</details>
{% endhint %}
