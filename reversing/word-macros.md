# Word Macros

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

### Junk Code

यह बहुत सामान्य है कि **जंक कोड जो कभी उपयोग नहीं होता** उसे मैक्रो के रिवर्सिंग को और कठिन बनाने के लिए पाया जाता है।\
उदाहरण के लिए, निम्नलिखित छवि में आप देख सकते हैं कि और यदि यह कभी सच नहीं होने वाला है, इसका उपयोग कुछ जंक और बेकार कोड को निष्पादित करने के लिए किया जाता है।

![](<../.gitbook/assets/image (369).png>)

### Macro Forms

**GetObject** फ़ंक्शन का उपयोग करके मैक्रो के फॉर्म से डेटा प्राप्त करना संभव है। इसका उपयोग विश्लेषण को कठिन बनाने के लिए किया जा सकता है। निम्नलिखित एक मैक्रो फॉर्म की फोटो है जिसका उपयोग **टेक्स्ट बॉक्स के अंदर डेटा छिपाने के लिए** किया जाता है (एक टेक्स्ट बॉक्स अन्य टेक्स्ट बॉक्स को छिपा सकता है):

![](<../.gitbook/assets/image (344).png>)

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
