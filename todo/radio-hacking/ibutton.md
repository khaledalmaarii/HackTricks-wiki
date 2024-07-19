# iButton

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

## Intro

iButton एक सामान्य नाम है जो एक इलेक्ट्रॉनिक पहचान कुंजी के लिए है जो एक **सिक्का के आकार के धातु के कंटेनर** में पैक की गई है। इसे **Dallas Touch** Memory या संपर्क मेमोरी भी कहा जाता है। हालांकि इसे अक्सर “चुंबकीय” कुंजी के रूप में गलत तरीके से संदर्भित किया जाता है, इसमें **कुछ भी चुंबकीय** नहीं है। वास्तव में, इसके अंदर एक पूर्ण विकसित **माइक्रोचिप** है जो एक डिजिटल प्रोटोकॉल पर काम करती है।

<figure><img src="../../.gitbook/assets/image (915).png" alt=""><figcaption></figcaption></figure>

### What is iButton? <a href="#what-is-ibutton" id="what-is-ibutton"></a>

आमतौर पर, iButton कुंजी और रीडर के भौतिक रूप को संदर्भित करता है - दो संपर्कों के साथ एक गोल सिक्का। इसके चारों ओर के फ्रेम के लिए, सबसे सामान्य प्लास्टिक धारक से लेकर छिद्र, अंगूठियों, लटकन आदि के कई रूप हैं।

<figure><img src="../../.gitbook/assets/image (1078).png" alt=""><figcaption></figcaption></figure>

जब कुंजी रीडर तक पहुँचती है, तो **संपर्क एक-दूसरे को छूते हैं** और कुंजी को **अपना** ID **प्रसारित** करने के लिए शक्ति मिलती है। कभी-कभी कुंजी को तुरंत **नहीं पढ़ा** जाता है क्योंकि **इंटरकॉम का संपर्क PSD** जितना होना चाहिए उससे बड़ा होता है। इसलिए कुंजी और रीडर के बाहरी आकृतियाँ छू नहीं पातीं। यदि ऐसा है, तो आपको रीडर की दीवारों में से एक पर कुंजी को दबाना होगा।

<figure><img src="../../.gitbook/assets/image (290).png" alt=""><figcaption></figcaption></figure>

### **1-Wire protocol** <a href="#id-1-wire-protocol" id="id-1-wire-protocol"></a>

Dallas कुंजी 1-wire प्रोटोकॉल का उपयोग करके डेटा का आदान-प्रदान करती है। डेटा ट्रांसफर के लिए केवल एक संपर्क (!!) दोनों दिशाओं में, मास्टर से दास और इसके विपरीत। 1-wire प्रोटोकॉल मास्टर-दास मॉडल के अनुसार काम करता है। इस टोपोलॉजी में, मास्टर हमेशा संचार शुरू करता है और दास इसके निर्देशों का पालन करता है।

जब कुंजी (दास) इंटरकॉम (मास्टर) से संपर्क करती है, तो कुंजी के अंदर का चिप चालू हो जाता है, इंटरकॉम द्वारा शक्ति प्राप्त करता है, और कुंजी प्रारंभिक होती है। इसके बाद इंटरकॉम कुंजी ID का अनुरोध करता है। अगला, हम इस प्रक्रिया को अधिक विस्तार से देखेंगे।

Flipper मास्टर और दास दोनों मोड में काम कर सकता है। कुंजी पढ़ने के मोड में, Flipper एक रीडर के रूप में कार्य करता है, यानी यह एक मास्टर के रूप में काम करता है। और कुंजी अनुकरण मोड में, फ्लिपर एक कुंजी होने का नाटक करता है, यह दास मोड में है।

### Dallas, Cyfral & Metakom keys

इन कुंजियों के काम करने के तरीके के बारे में जानकारी के लिए पृष्ठ देखें [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

### Attacks

iButtons पर Flipper Zero के साथ हमला किया जा सकता है:

{% content-ref url="flipper-zero/fz-ibutton.md" %}
[fz-ibutton.md](flipper-zero/fz-ibutton.md)
{% endcontent-ref %}

## References

* [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

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
