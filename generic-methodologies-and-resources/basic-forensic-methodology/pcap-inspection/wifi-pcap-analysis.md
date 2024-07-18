# Wifi Pcap Analysis

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

## Check BSSIDs

जब आप एक कैप्चर प्राप्त करते हैं जिसका मुख्य ट्रैफ़िक Wifi है, तो आप WireShark का उपयोग करके कैप्चर के सभी SSIDs की जांच करना शुरू कर सकते हैं _Wireless --> WLAN Traffic_:

![](<../../../.gitbook/assets/image (106).png>)

![](<../../../.gitbook/assets/image (492).png>)

### Brute Force

उस स्क्रीन के एक कॉलम में यह संकेत दिया गया है कि **क्या pcap के अंदर कोई प्रमाणीकरण पाया गया था**। यदि ऐसा है, तो आप इसे `aircrack-ng` का उपयोग करके Brute force करने की कोशिश कर सकते हैं:
```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```
उदाहरण के लिए, यह WPA पासफ़्रेज़ को पुनः प्राप्त करेगा जो एक PSK (पूर्व साझा कुंजी) की सुरक्षा करता है, जिसे बाद में ट्रैफ़िक को डिक्रिप्ट करने के लिए आवश्यक होगा।

## बीकन / साइड चैनल में डेटा

यदि आपको संदेह है कि **Wifi नेटवर्क के बीकन के अंदर डेटा लीक हो रहा है** तो आप निम्नलिखित फ़िल्टर का उपयोग करके नेटवर्क के बीकन की जांच कर सकते हैं: `wlan contains <NAMEofNETWORK>`, या `wlan.ssid == "NAMEofNETWORK"` फ़िल्टर किए गए पैकेट्स के अंदर संदिग्ध स्ट्रिंग्स के लिए खोजें।

## Wifi नेटवर्क में अज्ञात MAC पते खोजें

निम्नलिखित लिंक **Wifi नेटवर्क के अंदर डेटा भेजने वाली मशीनों** को खोजने के लिए उपयोगी होगा:

* `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

यदि आप पहले से ही **MAC पते जानते हैं, तो आप उन्हें आउटपुट से हटा सकते हैं** इस तरह की जांच जोड़कर: `&& !(wlan.addr==5c:51:88:31:a0:3b)`

एक बार जब आप नेटवर्क के अंदर संवाद कर रहे **अज्ञात MAC** पते का पता लगा लेते हैं, तो आप **फ़िल्टर** का उपयोग कर सकते हैं जैसे: `wlan.addr==<MAC address> && (ftp || http || ssh || telnet)` इसके ट्रैफ़िक को फ़िल्टर करने के लिए। ध्यान दें कि ftp/http/ssh/telnet फ़िल्टर उपयोगी हैं यदि आपने ट्रैफ़िक को डिक्रिप्ट किया है।

## ट्रैफ़िक डिक्रिप्ट करें

Edit --> Preferences --> Protocols --> IEEE 802.11--> Edit

![](<../../../.gitbook/assets/image (499).png>)

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
