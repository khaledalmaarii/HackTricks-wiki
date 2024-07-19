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


# कंटेनरों में SELinux

[रेडहैट डॉक्यूमेंट्स से परिचय और उदाहरण](https://www.redhat.com/sysadmin/privileged-flag-container-engines)

[SELinux](https://www.redhat.com/en/blog/latest-container-exploit-runc-can-be-blocked-selinux) एक **लेबलिंग** **सिस्टम** है। हर **प्रक्रिया** और हर **फाइल** सिस्टम ऑब्जेक्ट का एक **लेबल** होता है। SELinux नीतियाँ यह निर्धारित करती हैं कि **प्रक्रिया लेबल को सिस्टम पर अन्य सभी लेबल के साथ क्या करने की अनुमति है**।

कंटेनर इंजन **एकल सीमित SELinux लेबल** के साथ **कंटेनर प्रक्रियाएँ लॉन्च करते हैं**, आमतौर पर `container_t`, और फिर कंटेनर के अंदर कंटेनर को `container_file_t` लेबल करने के लिए सेट करते हैं। SELinux नीति नियम मूल रूप से कहते हैं कि **`container_t` प्रक्रियाएँ केवल `container_file_t` लेबल वाली फाइलों को पढ़/लिख/निष्पादित कर सकती हैं**। यदि एक कंटेनर प्रक्रिया कंटेनर से बाहर निकलती है और होस्ट पर सामग्री को लिखने का प्रयास करती है, तो लिनक्स कर्नेल एक्सेस को अस्वीकार कर देता है और केवल कंटेनर प्रक्रिया को `container_file_t` लेबल वाली सामग्री को लिखने की अनुमति देता है।
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
# SELinux उपयोगकर्ता

SELinux उपयोगकर्ता नियमित Linux उपयोगकर्ताओं के अतिरिक्त होते हैं। SELinux उपयोगकर्ता एक SELinux नीति का हिस्सा होते हैं। प्रत्येक Linux उपयोगकर्ता को नीति के हिस्से के रूप में एक SELinux उपयोगकर्ता से मैप किया जाता है। यह Linux उपयोगकर्ताओं को SELinux उपयोगकर्ताओं पर लगाए गए प्रतिबंधों और सुरक्षा नियमों और तंत्रों को विरासत में लेने की अनुमति देता है।

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
</details>
{% endhint %}
