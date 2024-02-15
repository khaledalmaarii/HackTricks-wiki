# चेकलिस्ट - स्थानीय Windows विशेषाधिकार उन्नयन

<details>

<summary><strong>जानें AWS हैकिंग को शून्य से हीरो तक</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> के साथ!</strong></summary>

HackTricks का समर्थन करने के अन्य तरीके:

* यदि आप अपनी **कंपनी का विज्ञापन HackTricks में देखना चाहते हैं** या **HackTricks को PDF में डाउनलोड करना चाहते हैं** तो [**सदस्यता योजनाएं देखें**](https://github.com/sponsors/carlospolop)!
* [**आधिकारिक PEASS और HackTricks स्वैग**](https://peass.creator-spring.com) प्राप्त करें
* हमारे विशेष [**NFTs**](https://opensea.io/collection/the-peass-family) संग्रह [**The PEASS Family**](https://opensea.io/collection/the-peass-family) खोजें
* **शामिल हों** 💬 [**डिस्कॉर्ड समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) या हमें **ट्विटर** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)** पर फॉलो** करें।
* **अपने हैकिंग ट्रिक्स साझा करें, PRs सबमिट करके** [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos में।

</details>

### **Windows स्थानीय विशेषाधिकार उन्नयन के लिए सर्वश्रेष्ठ उपकरण:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [सिस्टम जानकारी](windows-local-privilege-escalation/#system-info)

* [ ] [**सिस्टम जानकारी**](windows-local-privilege-escalation/#system-info) प्राप्त करें
* [ ] **कर्नेल** के लिए [**स्क्रिप्ट का उपयोग करके एक्सप्लॉइट्स खोजें**](windows-local-privilege-escalation/#version-exploits)
* **Google का उपयोग करें** कर्नेल **एक्सप्लॉइट्स** खोजने के लिए
* **searchsploit का उपयोग करें** कर्नेल **एक्सप्लॉइट्स** खोजने के लिए
* [**एनवायरनमेंट**](windows-local-privilege-escalation/#environment) में दिलचस्प जानकारी?
* [**PowerShell हिस्ट्री**](windows-local-privilege-escalation/#powershell-history) में पासवर्ड?
* [**इंटरनेट सेटिंग्स**](windows-local-privilege-escalation/#internet-settings) में दिलचस्प जानकारी?
* [**ड्राइव्स**](windows-local-privilege-escalation/#drives)?
* [**WSUS एक्सप्लॉइट**](windows-local-privilege-escalation/#wsus)?
* [**AlwaysInstallElevated**](windows-local-privilege-escalation/#alwaysinstallelevated)?

### [लॉगिंग/AV जाँच](windows-local-privilege-escalation/#enumeration)

* [ ] [**ऑडिट** ](windows-local-privilege-escalation/#audit-settings)और [**WEF** ](windows-local-privilege-escalation/#wef)सेटिंग्स जाँचें
* [ ] [**LAPS**](windows-local-privilege-escalation/#laps) जाँचें
* [ ] क्या [**WDigest** ](windows-local-privilege-escalation/#wdigest) सक्रिय है?
* [**LSA सुरक्षा**](windows-local-privilege-escalation/#lsa-protection)?
* [**क्रेडेंशियल्स गार्ड**](windows-local-privilege-escalation/#credentials-guard)[?](windows-local-privilege-escalation/#cached-credentials)
* [**कैश्ड क्रेडेंशियल्स**](windows-local-privilege-escalation/#cached-credentials) जाँचें?
* क्या कोई [**AV**](windows-av-bypass) है?
* [**AppLocker नीति**](authentication-credentials-uac-and-efs#applocker-policy)?
* [**UAC**](authentication-credentials-uac-and-efs/uac-user-account-control)?
* [**उपयोगकर्ता विशेषाधिकार**](windows-local-privilege-escalation/#users-and-groups)?
* [**वर्तमान** उपयोगकर्ता के **विशेषाधिकार**](windows-local-privilege-escalation/#users-and-groups) जाँचें
* क्या आप किसी **विशेषाधिकृत समूह के सदस्य** हैं (windows-local-privilege-escalation/#privileged-groups)?
* क्या आपके पास इन टोकन्स में से कोई सक्षम है: **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ? (windows-local-privilege-escalation/#token-manipulation)
* [**उपयोगकर्ता सत्र**](windows-local-privilege-escalation/#logged-users-sessions)?
* [**उपयोगकर्ता होम्स**](windows-local-privilege-escalation/#home-folders) जाँचें (पहुँच?)
* [**पासवर्ड नीति**](windows-local-privilege-escalation/#password-policy) जाँचें
* [**क्लिपबोर्ड**](windows-local-privilege-escalation/#get-the-content-of-the-clipboard) में क्या है?

### [नेटवर्क](windows-local-privilege-escalation/#network)

* **वर्तमान** [**नेटवर्क** **जानकारी**](windows-local-privilege-escalation/#network) जाँचें
* बाहर से प्रतिबंधित **छिपी हुई स्थानीय सेवाएं** जाँचें

### [चल रहे प्रक्रियाएँ](windows-local-privilege-escalation/#running-processes)

* प्रक्रियाओं के बाइनरी [**फ़ाइल और फ़ोल्डर अनुमतियाँ**](windows-local-privilege-escalation/#file-and-folder-permissions)
* [**मेमोरी पासवर्ड माइनिंग**](windows-local-privilege-escalation/#memory-password-mining)
* [**असुरक्षित GUI ऐप्स**](windows-local-privilege-escalation/#insecure-gui-apps)
* क्या आप **ProcDump.exe** के माध्यम से **दिलचस्प प्रक्रियाओं** से क्रेडेंशियल्स चुरा सकते हैं? (firefox, chrome, आदि ...)

### [सेवाएँ](windows-local-privilege-escalation/#services)

* [ ] क्या आप किसी सेवा को **संशोधित** कर सकते हैं? (windows-local-privilege-escalation#permissions)
* [ ] क्या आप किसी सेवा द्वारा **चलाया जाने वाला बाइनरी** **संशोधित** कर सकते हैं? (windows-local-privilege-escalation/#modify-service-binary-path)
* [ ] क्या आप किसी सेवा के **रजिस्ट्री** को **संशोधित** कर सकते हैं? (windows-local-privilege-escalation/#services-registry-modify-permissions)
* [ ] क्या आप किसी **अन-उद्धृत सेवा** बाइनरी **पथ** का लाभ उठा सकते हैं? (windows-local-privilege-escalation/#unquoted-service-paths)

### [**एप्लिकेशन्स**](windows-local-privilege-escalation/#applications)

* **स्थापित एप्लिकेशन्स** पर [**लेखन अनुमतियाँ**](windows-local-privilege-escalation/#write-permissions)
* [**स्टार्टअप एप्लिकेशन्स**](windows-local-privilege-escalation/#run-at-startup)
* **वंलरेबल** [**ड्राइवर्स**](windows-local-privilege-escalation/#drivers)

### [DLL हाइजैकिंग](windows-local-privilege-escalation/#path-dll-hijacking)

* क्या आप **PATH** के किसी भी फ़ोल्डर में **लिख सकते हैं**?
* क्या किसी भी ज्ञात सेवा बाइनरी है जो **किसी अस्तित्व न रखने वाली DLL** को लोड करने का प्रयास करती है?
* क्या आप किसी **बाइनरी फ़ोल्डर** में **लिख सकते हैं**?
### [नेटवर्क](windows-local-privilege-escalation/#network)

* [ ] नेटवर्क की जाँच करें (शेयर, इंटरफेस, रूट, पड़ोसी, ...)
* [ ] लोकलहोस्ट (127.0.0.1) पर सुनने वाली नेटवर्क सेवाओं पर विशेष ध्यान दें

### [Windows क्रेडेंशियल्स](windows-local-privilege-escalation/#windows-credentials)

* [ ] [**Winlogon** ](windows-local-privilege-escalation/#winlogon-credentials)क्रेडेंशियल्स
* [ ] [**Windows Vault**](windows-local-privilege-escalation/#credentials-manager-windows-vault) क्रेडेंशियल्स जिन्हें आप उपयोग कर सकते हैं?
* [ ] दिलचस्प [**DPAPI क्रेडेंशियल्स**](windows-local-privilege-escalation/#dpapi)?
* [ ] सहेजे गए [**Wifi नेटवर्कों**](windows-local-privilege-escalation/#wifi) के पासवर्ड?
* [ ] [**सहेजी गई RDP कनेक्शन्स**](windows-local-privilege-escalation/#saved-rdp-connections) में दिलचस्प जानकारी?
* [ ] हाल ही में चलाए गए कमांड्स में पासवर्ड?
* [ ] [**रिमोट डेस्कटॉप क्रेडेंशियल्स मैनेजर**](windows-local-privilege-escalation/#remote-desktop-credential-manager) पासवर्ड?
* [ ] [**AppCmd.exe** मौजूद है](windows-local-privilege-escalation/#appcmd-exe)? क्रेडेंशियल्स?
* [ ] [**SCClient.exe**](windows-local-privilege-escalation/#scclient-sccm)? DLL साइड लोडिंग?

### [फाइलें और रजिस्ट्री (क्रेडेंशियल्स)](windows-local-privilege-escalation/#files-and-registry-credentials)

* [ ] **Putty:** [**क्रेडेंशियल्स**](windows-local-privilege-escalation/#putty-creds) **और** [**SSH होस्ट की**](windows-local-privilege-escalation/#putty-ssh-host-keys) **कुंजियाँ**
* [ ] [**रजिस्ट्री में SSH कुंजियाँ**](windows-local-privilege-escalation/#ssh-keys-in-registry)?
* [ ] [**अनअटेंडेड फ़ाइलों**](windows-local-privilege-escalation/#unattended-files) में पासवर्ड?
* [ ] कोई [**SAM और SYSTEM**](windows-local-privilege-escalation/#sam-and-system-backups) बैकअप?
* [ ] [**क्लाउड क्रेडेंशियल्स**](windows-local-privilege-escalation/#cloud-credentials)?
* [ ] [**McAfee SiteList.xml**](windows-local-privilege-escalation/#mcafee-sitelist.xml) फ़ाइल?
* [**कैश्ड GPP पासवर्ड**](windows-local-privilege-escalation/#cached-gpp-pasword)?
* [ ] [**IIS वेब कॉन्फ़िग फ़ाइल**](windows-local-privilege-escalation/#iis-web-config) में पासवर्ड?
* [ ] दिलचस्प जानकारी [**वेब लॉगों**](windows-local-privilege-escalation/#logs) में?
* [ ] क्या आप उपयोगकर्ता से [**क्रेडेंशियल्स मांगना**](windows-local-privilege-escalation/#ask-for-credentials) चाहते हैं?
* [ ] रीसाइकल बिन में [**क्रेडेंशियल्स**](windows-local-privilege-escalation/#credentials-in-the-recyclebin) में दिलचस्प फ़ाइलें?
* [ ] अन्य [**रजिस्ट्री जिसमें क्रेडेंशियल्स हैं**](windows-local-privilege-escalation/#inside-the-registry)?
* [ ] [**ब्राउज़र डेटा**](windows-local-privilege-escalation/#browsers-history) में (डीबीएस, इतिहास, बुकमार्क्स, ...)?
* [**जेनेरिक पासवर्ड खोज**](windows-local-privilege-escalation/#generic-password-search-in-files-and-registry) फ़ाइलों और रजिस्ट्री में
* [**पासवर्ड खोजने के लिए उपकरण**](windows-local-privilege-escalation/#tools-that-search-for-passwords)

### [लीक हैंडलर्स](windows-local-privilege-escalation/#leaked-handlers)

* [ ] क्या आपके पास व्यवस्थापक द्वारा चलाए गए किसी प्रक्रिया के हैंडलर तक पहुँच है?

### [पाइप क्लाइंट इम्पर्सनेशन](windows-local-privilege-escalation/#named-pipe-client-impersonation)

* [ ] क्या आप इसका दुरुपयोग कर सकते हैं

<details>

<summary><strong>शून्य से हीरो तक AWS हैकिंग सीखें</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> के साथ!</strong></summary>

HackTricks का समर्थन करने के अन्य तरीके:

* अगर आप अपनी कंपनी का विज्ञापन HackTricks में देखना चाहते हैं या HackTricks को PDF में डाउनलोड करना चाहते हैं तो [**सब्सक्रिप्शन प्लान्स**](https://github.com/sponsors/carlospolop) देखें!
* [**आधिकारिक PEASS & HackTricks स्वैग**](https://peass.creator-spring.com) प्राप्त करें
* हमारे विशेष [**NFTs**](https://opensea.io/collection/the-peass-family) कलेक्शन [**The PEASS Family**](https://opensea.io/collection/the-peass-family) खोजें
* **शामिल हों** 💬 [**डिस्कॉर्ड समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) या हमें **ट्विटर** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live) पर **फॉलो** करें।
* **हैकिंग ट्रिक्स साझा करें** द्वारा PRs सबमिट करके [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github रेपो में।

</details>
