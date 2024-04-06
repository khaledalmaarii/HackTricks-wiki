# Checklist - Local Windows Privilege Escalation

<details>

<summary><strong>जानें AWS हैकिंग को शून्य से हीरो तक</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a> <strong>के साथ!</strong></summary>

HackTricks का समर्थन करने के अन्य तरीके:

* यदि आप अपनी **कंपनी का विज्ञापन HackTricks में देखना चाहते हैं** या **HackTricks को PDF में डाउनलोड करना चाहते हैं** तो [**सदस्यता योजनाएं देखें**](https://github.com/sponsors/carlospolop)!
* [**आधिकारिक PEASS और HackTricks स्वैग**](https://peass.creator-spring.com) प्राप्त करें
* हमारा संग्रह [**The PEASS Family**](https://opensea.io/collection/the-peass-family) खोजें, हमारा विशेष [**NFTs**](https://opensea.io/collection/the-peass-family) संग्रह
* **शामिल हों** 💬 [**डिस्कॉर्ड समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) या हमें **ट्विटर** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)\*\* पर फॉलो\*\* करें।
* **अपने हैकिंग ट्रिक्स साझा करें, हैकट्रिक्स** को पीआर जमा करके और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github रेपो में।

</details>

**Try Hard सुरक्षा समूह**

<figure><img src="../.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

***

### **Windows स्थानीय विशेषाधिकार उन्नयन वेक्टर्स खोजने के लिए सर्वश्रेष्ठ उपकरण:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [सिस्टम जानकारी](windows-local-privilege-escalation/#system-info)

* [ ] [**सिस्टम जानकारी**](windows-local-privilege-escalation/#system-info) प्राप्त करें
* [ ] **स्क्रिप्ट का उपयोग करके** **कर्नेल** [**शोधें**](windows-local-privilege-escalation/#version-exploits)
* [ ] **Google का उपयोग करें** कर्नेल **शोधने** के लिए
* [ ] **searchsploit का उपयोग करें** कर्नेल **शोधने** के लिए
* [ ] [**एनवायरनमेंट**](windows-local-privilege-escalation/#environment) में दिलचस्प जानकारी?
* [ ] [**PowerShell इतिहास**](windows-local-privilege-escalation/#powershell-history) में पासवर्ड?
* [ ] [**इंटरनेट सेटिंग्स**](windows-local-privilege-escalation/#internet-settings) में दिलचस्प जानकारी?
* [ ] [**ड्राइव्स**](windows-local-privilege-escalation/#drives)?
* [ ] [**WSUS उत्पीड़न**](windows-local-privilege-escalation/#wsus)?
* [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/#alwaysinstallelevated)?

### [लॉगिंग/AV गणना](windows-local-privilege-escalation/#enumeration)

* [**ऑडिट** ](windows-local-privilege-escalation/#audit-settings)और [**WEF** ](windows-local-privilege-escalation/#wef)सेटिंग्स जांचें
* [**LAPS**](windows-local-privilege-escalation/#laps) जांचें
* क्या [**WDigest** ](windows-local-privilege-escalation/#wdigest)सक्रिय है?
* [**LSA संरक्षण**](windows-local-privilege-escalation/#lsa-protection)?
* [**क्रेडेंशियल्स गार्ड**](windows-local-privilege-escalation/#credentials-guard)[?](windows-local-privilege-escalation/#cached-credentials)
* [**कैश क्रेडेंशियल्स**](windows-local-privilege-escalation/#cached-credentials) जांचें?
* क्या कोई [**AV**](https://github.com/carlospolop/hacktricks/blob/in/windows-hardening/windows-av-bypass/README.md) है?
* [**AppLocker नीति**](https://github.com/carlospolop/hacktricks/blob/in/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)?
* [**UAC**](https://github.com/carlospolop/hacktricks/blob/in/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
* [**उपयोगकर्ता विशेषाधिकार**](windows-local-privilege-escalation/#users-and-groups) जांचें
* [**वर्तमान** उपयोगकर्ता **विशेषाधिकार**](windows-local-privilege-escalation/#users-and-groups) जांचें
* क्या आप [**किसी विशेषाधिकार वाले समूह के सदस्य**](windows-local-privilege-escalation/#privileged-groups) हैं?
* क्या आपके पास इन टोकन्स में से कोई सक्षम हैं: **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
* [**उपयोगकर्ता सत्र**](windows-local-privilege-escalation/#logged-users-sessions) जांचें
* [**उपयोगकर्ता होम्स**](windows-local-privilege-escalation/#home-folders) जांचें (पहुंच?)
* [**पासवर्ड नीति**](windows-local-privilege-escalation/#password-policy) जांचें
* [**क्लिपबोर्ड**](windows-local-privilege-escalation/#get-the-content-of-the-clipboard) में क्या है?

### [नेटवर्क](windows-local-privilege-escalation/#network)

* **वर्तमान** [**नेटवर्क** **जानकारी**](windows-local-privilege-escalation/#network) जांचें
* बाहर की ओर सीमित **छिपी हुई स्थानीय सेवाएं** जांचें

### [चल रहे प्रक्रियाएं](windows-local-privilege-escalation/#running-processes)

* प्रक्रियाओं के बाइनरी [**फ़ाइल और फ़ोल्डर अनुमतियाँ**](windows-local-privilege-escalation/#file-and-folder-permissions) जांचें
* [**मेमोरी पासवर्ड माइनिंग**](windows-local-privilege-escalation/#memory-password-mining)
* [**असुरक्षित GUI ऐप्स**](windows-local-privilege-escalation/#insecure-gui-apps)
* क्या आप **ProcDump.exe** के माध्यम से **दिलचस्प प्रक्रियाओं** से क्रेडेंशियल्स चुरा सकते हैं? (firefox, chrome, आदि ...)

### [सेवाएं](windows-local-privilege-escalation/#services)

* क्या आप किसी सेवा को **संशोधित** कर सकते हैं?]\(windows-local-privilege-escalation#permissions)
* क्या आप किसी सेवा द्वारा निष्पादित किए जाने वाले **बाइनरी** को **संशोधित** कर सकते हैं?]\(windows-local-privilege-escalation/#modify-service-binary-path)
* क्या आप किसी सेवा के **रजिस्ट्री** को **संशोधित** कर सकते हैं?]\(windows-local-privilege-escalation/#services-registry-modify-permissions)
* क्या आप किसी **अन-उद्धृत सेवा** बाइनरी **पथ** का लाभ उठा सकते हैं?]\(windows-local-privilege-escalation/#unquoted-service-paths)

### [**एप्लिकेशन्स**](windows-local-privilege-escalation/#applications)

* **स्थापित एप्लिकेशन्स** पर [**लेखन अनुमतियाँ**](windows-local-privilege-escalation/#write-permissions) जांचें
* [**स्टार्टअप एप्लिकेशन्स**](windows-local-privilege-escalation/#run-at-startup) जांचें
* **वंलरेबल** [**ड्राइवर्स**](windows-local-privilege-escalation/#drivers) जांचें

### [DLL Hijacking](windows-local-privilege-escalation/#path-dll-hijacking)

* [ ] क्या आप **PATH के किसी भी फ़ोल्डर में लिख सकते हैं**?
* [ ] क्या कोई जाना-माना सेवा बाइनरी **किसी अस्तित्व रहित DLL को लोड करने की कोशिश करता है**?
* [ ] क्या आप **किसी भी बाइनरी फ़ोल्डर में लिख सकते हैं**?

### [नेटवर्क](windows-local-privilege-escalation/#network)

* [ ] नेटवर्क की जांच करें (शेयर, इंटरफेस, रूट, पड़ोसी, ...)
* [ ] लोकलहोस्ट (127.0.0.1) पर सुनने वाली नेटवर्क सेवाओं पर विशेष ध्यान दें

### [Windows क्रेडेंशियल्स](windows-local-privilege-escalation/#windows-credentials)

* [ ] [**Winlogon** ](windows-local-privilege-escalation/#winlogon-credentials)क्रेडेंशियल्स
* [ ] [**Windows Vault**](windows-local-privilege-escalation/#credentials-manager-windows-vault) क्रेडेंशियल्स जिन्हें आप उपयोग कर सकते हैं?
* [ ] दिलचस्प [**DPAPI क्रेडेंशियल्स**](windows-local-privilege-escalation/#dpapi)?
* [ ] सहेजे गए [**Wifi नेटवर्कों**](windows-local-privilege-escalation/#wifi) के पासवर्ड?
* [ ] [**सहेजी गई RDP कनेक्शनों**](windows-local-privilege-escalation/#saved-rdp-connections) में दिलचस्प जानकारी?
* [ ] हाल ही में चलाए गए कमांड्स में पासवर्ड?
* [ ] [**रिमोट डेस्कटॉप क्रेडेंशियल्स मैनेजर**](windows-local-privilege-escalation/#remote-desktop-credential-manager) पासवर्ड?
* [ ] [**AppCmd.exe** मौजूद है](windows-local-privilege-escalation/#appcmd-exe)? क्रेडेंशियल्स?
* [ ] [**SCClient.exe**](windows-local-privilege-escalation/#scclient-sccm)? DLL साइड लोडिंग?

### [फ़ाइलें और रजिस्ट्री (क्रेडेंशियल्स)](windows-local-privilege-escalation/#files-and-registry-credentials)

* [ ] **Putty:** [**क्रेडेंशियल्स**](windows-local-privilege-escalation/#putty-creds) **और** [**SSH होस्ट की**](windows-local-privilege-escalation/#putty-ssh-host-keys) **कुंजियाँ**
* [ ] [**रजिस्ट्री में SSH कुंजियाँ**](windows-local-privilege-escalation/#ssh-keys-in-registry)?
* [ ] [**अनअटेंडेड फ़ाइलों में**](windows-local-privilege-escalation/#unattended-files) पासवर्ड?
* [ ] कोई [**SAM और SYSTEM**](windows-local-privilege-escalation/#sam-and-system-backups) बैकअप?
* [ ] [**क्लाउड क्रेडेंशियल्स**](windows-local-privilege-escalation/#cloud-credentials)?
* [ ] [**McAfee SiteList.xml**](windows-local-privilege-escalation/#mcafee-sitelist.xml) फ़ाइल?
* [ ] [**GPP पासवर्ड**](windows-local-privilege-escalation/#cached-gpp-pasword) कैश किया गया?
* [ ] [**IIS वेब कॉन्फ़िग फ़ाइल में**](windows-local-privilege-escalation/#iis-web-config) पासवर्ड?
* [ ] [**वेब लॉगों में**](windows-local-privilege-escalation/#logs) दिलचस्प जानकारी?
* [ ] क्या आप उपयोगकर्ता से [**क्रेडेंशियल्स मांगना चाहते हैं**](windows-local-privilege-escalation/#ask-for-credentials)?
* [ ] रीसाइकल बिन में [**क्रेडेंशियल्स**](windows-local-privilege-escalation/#credentials-in-the-recyclebin) में दिलचस्प फ़ाइलें?
* [ ] अन्य [**रजिस्ट्री जिसमें क्रेडेंशियल्स हैं**](windows-local-privilege-escalation/#inside-the-registry)?
* [ ] [**ब्राउज़र डेटा में**](windows-local-privilege-escalation/#browsers-history) (डीबीएस, इतिहास, बुकमार्क्स, ...)?
* [ ] [**जेनेरिक पासवर्ड खोज**](windows-local-privilege-escalation/#generic-password-search-in-files-and-registry) फ़ाइलों और रजिस्ट्री में
* [ ] [**पासवर्ड खोजने के लिए उपकरण**](windows-local-privilege-escalation/#tools-that-search-for-passwords)

### [लीक हैंडलर्स](windows-local-privilege-escalation/#leaked-handlers)

* [ ] क्या आपके पास व्यवस्थापक द्वारा चलाए गए किसी प्रक्रिया के हैंडलर तक पहुँच है?

### [पाइप क्लाइंट इम्पर्सनेशन](windows-local-privilege-escalation/#named-pipe-client-impersonation)

* [ ] क्या आप इसे दुरुपयोग कर सकते हैं

**Try Hard सुरक्षा समूह**

<figure><img src="../.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

<details>

<summary><strong>जानें AWS हैकिंग को शून्य से हीरो तक</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a> <strong>के साथ!</strong></summary>

HackTricks का समर्थन करने के अन्य तरीके:

* यदि आप अपनी कंपनी का विज्ञापन **HackTricks** में देखना चाहते हैं या **HackTricks** को **PDF** में डाउनलोड करना चाहते हैं तो [**सब्सक्रिप्शन प्लान्स**](https://github.com/sponsors/carlospolop) देखें!
* [**आधिकारिक PEASS & HackTricks स्वैग**](https://peass.creator-spring.com) प्राप्त करें
* हमारे विशेष [**NFTs**](https://opensea.io/collection/the-peass-family) कलेक्शन [**The PEASS Family**](https://opensea.io/collection/the-peass-family) खोजें
* **शामिल हों** 💬 [**डिस्कॉर्ड समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) या हमें **ट्विटर** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live) पर **फ़ॉलो** करें।
* **अपने हैकिंग ट्रिक्स साझा करें** [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github रेपो में PR जमा करके।

</details>
