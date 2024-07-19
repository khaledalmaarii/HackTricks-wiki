# macOS Defensive Apps

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
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}

## Firewalls

* [**Little Snitch**](https://www.obdev.at/products/littlesnitch/index.html): यह प्रत्येक प्रक्रिया द्वारा बनाए गए हर कनेक्शन की निगरानी करेगा। मोड के आधार पर (चुपचाप कनेक्शन की अनुमति देना, चुपचाप कनेक्शन को अस्वीकार करना और चेतावनी देना) यह **आपको एक चेतावनी दिखाएगा** हर बार जब एक नया कनेक्शन स्थापित होता है। इसमें सभी जानकारी देखने के लिए एक बहुत अच्छा GUI भी है।
* [**LuLu**](https://objective-see.org/products/lulu.html): Objective-See फ़ायरवॉल। यह एक बुनियादी फ़ायरवॉल है जो संदिग्ध कनेक्शनों के लिए आपको चेतावनी देगा (इसमें एक GUI है लेकिन यह Little Snitch के GUI जितना शानदार नहीं है)।

## Persistence detection

* [**KnockKnock**](https://objective-see.org/products/knockknock.html): Objective-See एप्लिकेशन जो कई स्थानों में खोज करेगा जहाँ **malware स्थायी हो सकता है** (यह एक एकल-शॉट उपकरण है, निगरानी सेवा नहीं)।
* [**BlockBlock**](https://objective-see.org/products/blockblock.html): KnockKnock की तरह, जो स्थिरता उत्पन्न करने वाली प्रक्रियाओं की निगरानी करता है।

## Keyloggers detection

* [**ReiKey**](https://objective-see.org/products/reikey.html): Objective-See एप्लिकेशन जो **keyloggers** को खोजने के लिए है जो कीबोर्ड "इवेंट टैप" स्थापित करते हैं।
