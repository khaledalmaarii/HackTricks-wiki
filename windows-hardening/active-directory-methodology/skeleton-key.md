# Skeleton Key

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

## Skeleton Key Attack

**Skeleton Key हमला** एक जटिल तकनीक है जो हमलावरों को **Active Directory प्रमाणीकरण को बायपास करने** की अनुमति देती है, **डोमेन कंट्रोलर में एक मास्टर पासवर्ड इंजेक्ट करके**। यह हमलावर को **किसी भी उपयोगकर्ता के रूप में प्रमाणीकरण** करने में सक्षम बनाता है बिना उनके पासवर्ड के, प्रभावी रूप से **उन्हें डोमेन तक असीमित पहुंच प्रदान करता है**।

इसे [Mimikatz](https://github.com/gentilkiwi/mimikatz) का उपयोग करके किया जा सकता है। इस हमले को अंजाम देने के लिए, **डोमेन एडमिन अधिकार आवश्यक हैं**, और हमलावर को प्रत्येक डोमेन कंट्रोलर को लक्षित करना होगा ताकि एक व्यापक उल्लंघन सुनिश्चित हो सके। हालाँकि, हमले का प्रभाव अस्थायी है, क्योंकि **डोमेन कंट्रोलर को पुनरारंभ करने से मैलवेयर समाप्त हो जाता है**, जिससे निरंतर पहुंच के लिए पुनः कार्यान्वयन की आवश्यकता होती है।

**हमले को अंजाम देने के लिए** एक ही कमांड की आवश्यकता होती है: `misc::skeleton`.

## Mitigations

ऐसे हमलों के खिलाफ निवारण रणनीतियों में उन विशिष्ट इवेंट आईडी की निगरानी करना शामिल है जो सेवाओं की स्थापना या संवेदनशील विशेषाधिकारों के उपयोग को इंगित करते हैं। विशेष रूप से, सिस्टम इवेंट आईडी 7045 या सुरक्षा इवेंट आईडी 4673 की तलाश करना संदिग्ध गतिविधियों को प्रकट कर सकता है। इसके अतिरिक्त, `lsass.exe` को एक संरक्षित प्रक्रिया के रूप में चलाना हमलावरों के प्रयासों को काफी बाधित कर सकता है, क्योंकि इसके लिए उन्हें एक कर्नेल मोड ड्राइवर का उपयोग करना आवश्यक है, जिससे हमले की जटिलता बढ़ जाती है।

यहाँ सुरक्षा उपायों को बढ़ाने के लिए PowerShell कमांड हैं:

- संदिग्ध सेवाओं की स्थापना का पता लगाने के लिए, उपयोग करें: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*"}`

- विशेष रूप से, Mimikatz के ड्राइवर का पता लगाने के लिए, निम्नलिखित कमांड का उपयोग किया जा सकता है: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*" -and $_.message -like "*mimidrv*"}`

- `lsass.exe` को मजबूत करने के लिए, इसे एक संरक्षित प्रक्रिया के रूप में सक्षम करना अनुशंसित है: `New-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name RunAsPPL -Value 1 -Verbose`

सिस्टम पुनरारंभ के बाद सत्यापन करना महत्वपूर्ण है यह सुनिश्चित करने के लिए कि सुरक्षा उपाय सफलतापूर्वक लागू किए गए हैं। यह किया जा सकता है: `Get-WinEvent -FilterHashtable @{Logname='System';ID=12} | ?{$_.message -like "*protected process*`

## References
* [https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/](https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/)

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
