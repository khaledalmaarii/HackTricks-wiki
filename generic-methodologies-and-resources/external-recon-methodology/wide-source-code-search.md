# Wide Source Code Search

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

इस पृष्ठ का लक्ष्य **प्लेटफार्मों की गणना करना है जो कोड** (शाब्दिक या regex) को हजारों/लाखों रिपोजिटरी में एक या अधिक प्लेटफार्मों में खोजने की अनुमति देते हैं।

यह कई अवसरों पर **लीक की गई जानकारी** या **कमजोरियों** के पैटर्न की खोज में मदद करता है।

* [**SourceGraph**](https://sourcegraph.com/search): लाखों रिपोजिटरी में खोजें। इसमें एक मुफ्त संस्करण और एक एंटरप्राइज संस्करण (15 दिनों के लिए मुफ्त) है। यह regex का समर्थन करता है।
* [**Github Search**](https://github.com/search): Github में खोजें। यह regex का समर्थन करता है।
* शायद [**Github Code Search**](https://cs.github.com/) की जांच करना भी उपयोगी हो।
* [**Gitlab Advanced Search**](https://docs.gitlab.com/ee/user/search/advanced\_search.html): Gitlab प्रोजेक्ट्स में खोजें। regex का समर्थन करता है।
* [**SearchCode**](https://searchcode.com/): लाखों प्रोजेक्ट्स में कोड खोजें।

{% hint style="warning" %}
जब आप किसी रिपोजिटरी में लीक की तलाश कर रहे हों और कुछ ऐसा चलाते हैं जैसे `git log -p` तो न भूलें कि वहाँ **अन्य शाखाएँ हो सकती हैं जिनमें अन्य कमिट्स** हो सकते हैं जिनमें रहस्य हो सकते हैं!
{% endhint %}

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
