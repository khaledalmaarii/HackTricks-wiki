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

डिवाइस स्टार्टअप कॉन्फ़िगरेशन और बूटलोडर जैसे U-boot को संशोधित करने के लिए निम्नलिखित चरणों की सिफारिश की जाती है:

1. **बूटलोडर के इंटरप्रेटर शेल तक पहुँचें**:
- बूट के दौरान, बूटलोडर के इंटरप्रेटर शेल तक पहुँचने के लिए "0", स्पेस, या अन्य पहचाने गए "जादुई कोड" दबाएँ।

2. **बूट तर्कों को संशोधित करें**:
- शेल कमांड के निष्पादन की अनुमति देने के लिए बूट तर्कों में '`init=/bin/sh`' जोड़ने के लिए निम्नलिखित कमांड निष्पादित करें:
%%%
#printenv
#setenv bootargs=console=ttyS0,115200 mem=63M root=/dev/mtdblock3 mtdparts=sflash:<partitiionInfo> rootfstype=<fstype> hasEeprom=0 5srst=0 init=/bin/sh
#saveenv
#boot
%%%

3. **TFTP सर्वर सेटअप करें**:
- स्थानीय नेटवर्क पर छवियों को लोड करने के लिए एक TFTP सर्वर कॉन्फ़िगर करें:
%%%
#setenv ipaddr 192.168.2.2 #डिवाइस का स्थानीय IP
#setenv serverip 192.168.2.1 #TFTP सर्वर IP
#saveenv
#reset
#ping 192.168.2.1 #नेटवर्क एक्सेस की जाँच करें
#tftp ${loadaddr} uImage-3.6.35 #loadaddr फ़ाइल को लोड करने के लिए पता लेता है और TFTP सर्वर पर छवि का फ़ाइल नाम
%%%

4. **`ubootwrite.py` का उपयोग करें**:
- रूट एक्सेस प्राप्त करने के लिए U-boot छवि को लिखने और संशोधित फर्मवेयर को पुश करने के लिए `ubootwrite.py` का उपयोग करें।

5. **डिबग सुविधाओं की जाँच करें**:
- यह सत्यापित करें कि क्या विस्तृत लॉगिंग, मनमाने कर्नेल लोड करने, या अविश्वसनीय स्रोतों से बूट करने जैसी डिबग सुविधाएँ सक्षम हैं।

6. **सावधानीपूर्वक हार्डवेयर हस्तक्षेप**:
- डिवाइस बूट-अप अनुक्रम के दौरान एक पिन को ग्राउंड से जोड़ने और SPI या NAND फ्लैश चिप्स के साथ बातचीत करते समय सावधान रहें, विशेष रूप से कर्नेल के डिकंप्रेस होने से पहले। पिन को शॉर्ट करने से पहले NAND फ्लैश चिप के डेटा शीट की जांच करें।

7. **रोग DHCP सर्वर कॉन्फ़िगर करें**:
- PXE बूट के दौरान डिवाइस द्वारा ग्रहण करने के लिए दुर्भावनापूर्ण पैरामीटर के साथ एक रोग DHCP सर्वर सेट करें। Metasploit के (MSF) DHCP सहायक सर्वर जैसे उपकरणों का उपयोग करें। डिवाइस स्टार्टअप प्रक्रियाओं के लिए इनपुट मान्यता का परीक्षण करने के लिए कमांड इंजेक्शन कमांड जैसे `'a";/bin/sh;#'` के साथ 'FILENAME' पैरामीटर को संशोधित करें।

**नोट**: डिवाइस पिन के साथ भौतिक इंटरैक्शन से संबंधित चरणों (*तारों के साथ चिह्नित) को डिवाइस को नुकसान से बचाने के लिए अत्यधिक सावधानी के साथ किया जाना चाहिए।

## References
* [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)


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
