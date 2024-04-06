# Android Forensics

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks का समर्थन करने के अन्य तरीके:

* यदि आप अपनी **कंपनी का विज्ञापन HackTricks में देखना चाहते हैं** या **HackTricks को PDF में डाउनलोड करना चाहते हैं** तो [**सब्सक्रिप्शन प्लान्स**](https://github.com/sponsors/carlospolop) देखें!
* [**आधिकारिक PEASS & HackTricks स्वैग**](https://peass.creator-spring.com) प्राप्त करें
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) की खोज करें, हमारा विशेष [**NFTs**](https://opensea.io/collection/the-peass-family) संग्रह
* 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) में **शामिल हों** या [**telegram group**](https://t.me/peass) में या **Twitter** 🐦 पर मुझे **फॉलो** करें [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **HackTricks** के [**github repos**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) में PRs सबमिट करके अपनी हैकिंग ट्रिक्स शेयर करें।

</details>

## Locked Device

एक Android डिवाइस से डेटा निकालना शुरू करने के लिए उसे अनलॉक होना चाहिए। अगर यह लॉक है तो आप:

* जांचें कि क्या डिवाइस में USB के माध्यम से डिबगिंग सक्रिय है।
* संभावित [smudge attack](https://www.usenix.org/legacy/event/woot10/tech/full\_papers/Aviv.pdf) के लिए जांचें।
* [Brute-force](https://www.cultofmac.com/316532/this-brute-force-device-can-crack-any-iphones-pin-code/) के साथ प्रयास करें।

## Data Adquisition

[android backup using adb](../mobile-pentesting/android-app-pentesting/adb-commands.md#backup) बनाएं और इसे [Android Backup Extractor](https://sourceforge.net/projects/adbextractor/) का उपयोग करके निकालें: `java -jar abe.jar unpack file.backup file.tar`

### If root access or physical connection to JTAG interface

* `cat /proc/partitions` (फ्लैश मेमोरी के पथ की खोज करें, आमतौर पर पहली प्रविष्टि _mmcblk0_ होती है और यह पूरी फ्लैश मेमोरी के लिए होती है)।
* `df /data` (सिस्टम के ब्लॉक साइज का पता लगाएं)।
* dd if=/dev/block/mmcblk0 of=/sdcard/blk0.img bs=4096 (ब्लॉक साइज से एकत्रित जानकारी के साथ इसे निष्पादित करें)।

### Memory

Linux Memory Extractor (LiME) का उपयोग करके RAM जानकारी निकालें। यह एक कर्नेल एक्सटेंशन है जिसे adb के माध्यम से लोड किया जाना चाहिए।

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks का समर्थन करने के अन्य तरीके:

* यदि आप अपनी **कंपनी का विज्ञापन HackTricks में देखना चाहते हैं** या **HackTricks को PDF में डाउनलोड करना चाहते हैं** तो [**सब्सक्रिप्शन प्लान्स**](https://github.com/sponsors/carlospolop) देखें!
* [**आधिकारिक PEASS & HackTricks स्वैग**](https://peass.creator-spring.com) प्राप्त करें
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) की खोज करें, हमारा विशेष [**NFTs**](https://opensea.io/collection/the-peass-family) संग्रह
* 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) में **शामिल हों** या [**telegram group**](https://t.me/peass) में या **Twitter** 🐦 पर मुझे **फॉलो** करें [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **HackTricks** के [**github repos**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) में PRs सबमिट करके अपनी हैकिंग ट्रिक्स शेयर करें।

</details>
