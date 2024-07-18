# Android Forensics

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

## Locked Device

Android डिवाइस से डेटा निकालने के लिए इसे अनलॉक करना आवश्यक है। यदि यह लॉक है, तो आप:

* जांचें कि क्या डिवाइस में USB के माध्यम से डिबगिंग सक्रिय है।
* संभावित [smudge attack](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Aviv.pdf) के लिए जांचें।
* [Brute-force](https://www.cultofmac.com/316532/this-brute-force-device-can-crack-any-iphones-pin-code/) के साथ प्रयास करें।

## Data Adquisition

[adb का उपयोग करके एक android बैकअप बनाएं](../mobile-pentesting/android-app-pentesting/adb-commands.md#backup) और इसे [Android Backup Extractor](https://sourceforge.net/projects/adbextractor/) का उपयोग करके निकालें: `java -jar abe.jar unpack file.backup file.tar`

### यदि रूट एक्सेस या JTAG इंटरफेस के लिए भौतिक कनेक्शन है

* `cat /proc/partitions` (फ्लैश मेमोरी के पथ की खोज करें, सामान्यतः पहला प्रविष्टि _mmcblk0_ होती है और यह पूरे फ्लैश मेमोरी से संबंधित होती है)।
* `df /data` (सिस्टम के ब्लॉक आकार का पता लगाएं)।
* dd if=/dev/block/mmcblk0 of=/sdcard/blk0.img bs=4096 (ब्लॉक आकार से एकत्रित जानकारी के साथ इसे निष्पादित करें)।

### Memory

RAM जानकारी निकालने के लिए Linux Memory Extractor (LiME) का उपयोग करें। यह एक कर्नेल एक्सटेंशन है जिसे adb के माध्यम से लोड किया जाना चाहिए।

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
