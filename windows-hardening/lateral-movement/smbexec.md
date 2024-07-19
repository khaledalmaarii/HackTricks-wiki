# SmbExec/ScExec

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

## How it Works

**Smbexec** एक उपकरण है जिसका उपयोग Windows सिस्टम पर दूरस्थ कमांड निष्पादन के लिए किया जाता है, जो **Psexec** के समान है, लेकिन यह लक्षित प्रणाली पर कोई दुर्भावनापूर्ण फ़ाइलें नहीं रखता है।

### Key Points about **SMBExec**

- यह लक्षित मशीन पर एक अस्थायी सेवा (उदाहरण के लिए, "BTOBTO") बनाकर cmd.exe (%COMSPEC%) के माध्यम से कमांड निष्पादित करता है, बिना किसी बाइनरी को गिराए।
- इसके छिपे हुए दृष्टिकोण के बावजूद, यह प्रत्येक निष्पादित कमांड के लिए इवेंट लॉग उत्पन्न करता है, जो एक गैर-इंटरैक्टिव "शेल" का एक रूप प्रदान करता है।
- **Smbexec** का उपयोग करके कनेक्ट करने के लिए कमांड इस प्रकार दिखता है:
```bash
smbexec.py WORKGROUP/genericuser:genericpassword@10.10.10.10
```
### Executing Commands Without Binaries

- **Smbexec** सेवा binPaths के माध्यम से सीधे कमांड निष्पादन की अनुमति देता है, जिससे लक्ष्य पर भौतिक बाइनरी की आवश्यकता समाप्त हो जाती है।
- यह विधि Windows लक्ष्य पर एक बार के लिए कमांड निष्पादित करने के लिए उपयोगी है। उदाहरण के लिए, इसे Metasploit के `web_delivery` मॉड्यूल के साथ जोड़ने से PowerShell-लक्षित रिवर्स मीटरप्रीटर पेलोड का निष्पादन संभव होता है।
- हमलावर की मशीन पर एक दूरस्थ सेवा बनाकर जिसमें binPath को cmd.exe के माध्यम से प्रदान किए गए कमांड को चलाने के लिए सेट किया गया है, पेलोड को सफलतापूर्वक निष्पादित करना संभव है, callback और पेलोड निष्पादन को Metasploit लिस्नर के साथ प्राप्त करना, भले ही सेवा प्रतिक्रिया त्रुटियाँ उत्पन्न हों।

### Commands Example

Creating and starting the service can be accomplished with the following commands:
```bash
sc create [ServiceName] binPath= "cmd.exe /c [PayloadCommand]"
sc start [ServiceName]
```
FOr further details check [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

## References
* [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

{% hint style="success" %}
सीखें और AWS हैकिंग का अभ्यास करें:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
सीखें और GCP हैकिंग का अभ्यास करें: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks का समर्थन करें</summary>

* [**सदस्यता योजनाएँ**](https://github.com/sponsors/carlospolop) देखें!
* **हमारे** 💬 [**Discord समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) में शामिल हों या **हमारे** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** का पालन करें।**
* **हैकिंग ट्रिक्स साझा करें और** [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) गिटहब रिपोजिटरी में PRs सबमिट करें।

</details>
{% endhint %}
