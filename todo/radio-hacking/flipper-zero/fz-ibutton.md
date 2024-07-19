# FZ - iButton

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

iButton के बारे में अधिक जानकारी के लिए देखें:

{% content-ref url="../ibutton.md" %}
[ibutton.md](../ibutton.md)
{% endcontent-ref %}

## Design

निम्नलिखित चित्र का **नीला** भाग वह है जहाँ आपको **वास्तविक iButton** को **रखना** होगा ताकि Flipper इसे **पढ़ सके।** **हरा** भाग वह है जहाँ आपको **Flipper Zero** के साथ रीडर को **सही तरीके से iButton का अनुकरण** करने के लिए **छूना** होगा।

<figure><img src="../../../.gitbook/assets/image (565).png" alt=""><figcaption></figcaption></figure>

## Actions

### Read

रीड मोड में Flipper iButton कुंजी के छूने का इंतजार कर रहा है और तीन प्रकार की कुंजियों: **Dallas, Cyfral, और Metakom** में से किसी को भी समझने में सक्षम है। Flipper **स्वयं कुंजी के प्रकार का पता लगाएगा।** कुंजी प्रोटोकॉल का नाम ID संख्या के ऊपर स्क्रीन पर प्रदर्शित होगा।

### Add manually

यह **हाथ से जोड़ना** संभव है एक iButton प्रकार: **Dallas, Cyfral, और Metakom**

### **Emulate**

यह **अनुकरण करना** संभव है सहेजे गए iButtons (पढ़े गए या हाथ से जोड़े गए)।

{% hint style="info" %}
यदि आप Flipper Zero के अपेक्षित संपर्कों को रीडर को छूने में असमर्थ हैं, तो आप **बाहरी GPIO का उपयोग कर सकते हैं:**
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (138).png" alt=""><figcaption></figcaption></figure>

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
