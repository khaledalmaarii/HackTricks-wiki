# Hash Length Extension Attack

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


## Summary of the attack

कल्पना कीजिए एक सर्वर है जो कुछ डेटा को एक ज्ञात स्पष्ट पाठ डेटा में एक गुप्त को जोड़कर और फिर उस डेटा को हैश करके **हस्ताक्षर** कर रहा है। यदि आप जानते हैं:

* **गुप्त की लंबाई** (इसे दिए गए लंबाई रेंज से भी ब्रूटफोर्स किया जा सकता है)
* **स्पष्ट पाठ डेटा**
* **एल्गोरिदम (और यह इस हमले के प्रति संवेदनशील है)**
* **पैडिंग ज्ञात है**
* आमतौर पर एक डिफ़ॉल्ट का उपयोग किया जाता है, इसलिए यदि अन्य 3 आवश्यकताएँ पूरी होती हैं, तो यह भी है
* पैडिंग गुप्त + डेटा की लंबाई के आधार पर भिन्न होती है, यही कारण है कि गुप्त की लंबाई की आवश्यकता है

तो, एक **हमलावर** के लिए **डेटा जोड़ना** और **पिछले डेटा + जोड़ा गया डेटा** के लिए एक वैध **हस्ताक्षर** उत्पन्न करना संभव है।

### How?

बुनियादी रूप से संवेदनशील एल्गोरिदम पहले **डेटा के एक ब्लॉक को हैश करके** हैश उत्पन्न करते हैं, और फिर, **पहले से** बनाए गए **हैश** (राज्य) से, वे **अगले डेटा के ब्लॉक को जोड़ते हैं** और **इसे हैश करते हैं**।

फिर, कल्पना कीजिए कि गुप्त "गुप्त" है और डेटा "डेटा" है, "गुप्तडेटा" का MD5 6036708eba0d11f6ef52ad44e8b74d5b है।\
यदि एक हमलावर "जोड़ें" स्ट्रिंग को जोड़ना चाहता है, तो वह कर सकता है:

* 64 "A"s का MD5 उत्पन्न करें
* पहले से प्रारंभ किए गए हैश की स्थिति को 6036708eba0d11f6ef52ad44e8b74d5b में बदलें
* "जोड़ें" स्ट्रिंग जोड़ें
* हैश को समाप्त करें और परिणामी हैश "गुप्त" + "डेटा" + "पैडिंग" + "जोड़ें" के लिए एक **वैध** होगा

### **Tool**

{% embed url="https://github.com/iagox86/hash_extender" %}

### References

आप इस हमले को अच्छी तरह से समझा सकते हैं [https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)



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
