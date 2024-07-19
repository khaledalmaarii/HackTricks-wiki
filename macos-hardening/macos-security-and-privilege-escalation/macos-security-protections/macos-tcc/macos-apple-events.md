# macOS Apple Events

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

## Basic Information

**Apple Events** एप्पल के macOS में एक विशेषता है जो अनुप्रयोगों को एक-दूसरे के साथ संवाद करने की अनुमति देती है। ये **Apple Event Manager** का हिस्सा हैं, जो macOS ऑपरेटिंग सिस्टम का एक घटक है जो इंटरप्रोसेस संचार को संभालने के लिए जिम्मेदार है। यह प्रणाली एक अनुप्रयोग को दूसरे अनुप्रयोग को एक संदेश भेजने की अनुमति देती है ताकि वह एक विशेष ऑपरेशन कर सके, जैसे कि एक फ़ाइल खोलना, डेटा प्राप्त करना, या एक आदेश निष्पादित करना।

मिना डेमन `/System/Library/CoreServices/appleeventsd` है जो सेवा `com.apple.coreservices.appleevents` को पंजीकृत करता है।

हर अनुप्रयोग जो घटनाएँ प्राप्त कर सकता है, इस डेमन के साथ अपने Apple Event Mach Port की जांच करेगा। और जब एक ऐप इसे एक घटना भेजना चाहता है, तो ऐप इस पोर्ट को डेमन से अनुरोध करेगा।

सैंडबॉक्स किए गए अनुप्रयोगों को घटनाएँ भेजने के लिए `allow appleevent-send` और `(allow mach-lookup (global-name "com.apple.coreservices.appleevents))` जैसे विशेषाधिकार की आवश्यकता होती है। ध्यान दें कि `com.apple.security.temporary-exception.apple-events` जैसे अधिकार उन लोगों को प्रतिबंधित कर सकते हैं जिनके पास घटनाएँ भेजने की अनुमति है, जिसके लिए `com.apple.private.appleevents` जैसे अधिकार की आवश्यकता होगी।

{% hint style="success" %}
It's possible to use the env variable **`AEDebugSends`** in order to log informtion about the message sent:
```bash
AEDebugSends=1 osascript -e 'tell application "iTerm" to activate'
```
{% endhint %}

{% hint style="success" %}
सीखें और AWS हैकिंग का अभ्यास करें:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
सीखें और GCP हैकिंग का अभ्यास करें: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks का समर्थन करें</summary>

* [**सदस्यता योजनाएँ**](https://github.com/sponsors/carlospolop) देखें!
* **हमारे** 💬 [**Discord समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) में शामिल हों या **हमें** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** पर फॉलो करें।**
* **हैकिंग ट्रिक्स साझा करें और** [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) गिटहब रिपोजिटरी में PR सबमिट करें।

</details>
{% endhint %}
