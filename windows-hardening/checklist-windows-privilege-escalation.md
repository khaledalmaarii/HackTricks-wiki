# चेकलिस्ट - स्थानीय Windows विशेषाधिकार वृद्धि

<details>

<summary><strong>AWS हैकिंग सीखें शून्य से नायक तक</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks का समर्थन करने के अन्य तरीके:

* यदि आप अपनी **कंपनी का विज्ञापन HackTricks में देखना चाहते हैं** या **HackTricks को PDF में डाउनलोड करना चाहते हैं**, तो [**सब्सक्रिप्शन प्लान्स**](https://github.com/sponsors/carlospolop) देखें!
* [**आधिकारिक PEASS & HackTricks स्वैग**](https://peass.creator-spring.com) प्राप्त करें
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) की खोज करें, हमारा विशेष [**NFTs**](https://opensea.io/collection/the-peass-family) संग्रह
* 💬 [**Discord समूह**](https://discord.gg/hRep4RUj7f) में **शामिल हों** या [**telegram समूह**](https://t.me/peass) में या **Twitter** 🐦 पर मुझे **फॉलो** करें [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **HackTricks** और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos में PRs सबमिट करके अपनी हैकिंग ट्रिक्स साझा करें।

</details>

### **Windows स्थानीय विशेषाधिकार वृद्धि वेक्टर्स की खोज के लिए सर्वोत्तम उपकरण:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [सिस्टम जानकारी](windows-local-privilege-escalation/#system-info)

* [ ] [**सिस्टम जानकारी**](windows-local-privilege-escalation/#system-info) प्राप्त करें
* [ ] स्क्रिप्ट्स का उपयोग करके **कर्नेल** [**एक्सप्लॉइट्स की खोज करें**](windows-local-privilege-escalation/#version-exploits)
* [ ] कर्नेल **एक्सप्लॉइट्स के लिए Google पर खोज करें**
* [ ] कर्नेल **एक्सप्लॉइट्स के लिए searchsploit का उपयोग करें**
* [ ] [**env vars**](windows-local-privilege-escalation/#environment) में दिलचस्प जानकारी?
* [ ] [**PowerShell इतिहास**](windows-local-privilege-escalation/#powershell-history) में पासवर्ड?
* [ ] [**इंटरनेट सेटिंग्स**](windows-local-privilege-escalation/#internet-settings) में दिलचस्प जानकारी?
* [ ] [**ड्राइव्स**](windows-local-privilege-escalation/#drives)?
* [ ] [**WSUS एक्सप्लॉइट**](windows-local-privilege-escalation/#wsus)?
* [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/#alwaysinstallelevated)?

### [लॉगिंग/AV गणना](windows-local-privilege-escalation/#enumeration)

* [ ] [**ऑडिट** ](windows-local-privilege-escalation/#audit-settings)और [**WEF** ](windows-local-privilege-escalation/#wef)सेटिंग्स की जाँच करें
* [ ] [**LAPS**](windows-local-privilege-escalation/#laps) की जाँच करें
* [ ] जाँचें कि [**WDigest** ](windows-local-privilege-escalation/#wdigest)सक्रिय है या नहीं
* [ ] [**LSA सुरक्षा**](windows-local-privilege-escalation/#lsa-protection)?
* [ ] [**क्रेडेंशियल्स गार्ड**](windows-local-privilege-escalation/#credentials-guard)[?](windows-local-privilege-escalation/#cached-credentials)
* [ ] [**कैश्ड क्रेडेंशियल्स**](windows-local-privilege-escalation/#cached-credentials)?
* [ ] कोई [**AV**](windows-av-bypass) की जाँच करें
* [ ] [**AppLocker नीति**](authentication-credentials-uac-and-efs#applocker-policy)?
* [ ] [**UAC**](authentication-credentials-uac-and-efs/uac-user-account-control)
* [ ] [**उपयोगकर्ता विशेषाधिकार**](windows-local-privilege-escalation/#users-and-groups)
* [ ] [**वर्तमान** उपयोगकर्ता **विशेषाधिकार**](windows-local-privilege-escalation/#users-and-groups) की जाँच करें
* [ ] क्या आप [**किसी विशेषाधिकार प्राप्त समूह के सदस्य हैं**](windows-local-privilege-escalation/#privileged-groups)?
* [ ] जाँचें कि क्या आपके पास [इनमें से कोई भी टोकन सक्षम है](windows-local-privilege-escalation/#token-manipulation): **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
* [ ] [**उपयोगकर्ता सत्र**](windows-local-privilege-escalation/#logged-users-sessions)?
* [ ] [**उपयोगकर्ता घरों**](windows-local-privilege-escalation/#home-folders) की जाँच करें (पहुँच?)
* [ ] [**पासवर्ड नीति**](windows-local-privilege-escalation/#password-policy) की जाँच करें
* [ ] [**क्लिपबोर्ड के अंदर क्या है**](windows-local-privilege-escalation/#get-the-content-of-the-clipboard)?

### [नेटवर्क](windows-local-privilege-escalation/#network)

* [ ] [**वर्तमान** **नेटवर्क** **जानकारी**](windows-local-privilege-escalation/#network) की जाँच करें
* [ ] बाहरी के लिए प्रतिबंधित **छिपी हुई स्थानीय सेवाओं** की जाँच करें

### [चल रही प्रक्रियाएँ](windows-local-privilege-escalation/#running-processes)

* [ ] प्रक्रियाओं की बाइनरी [**फ़ाइल और फ़ोल्डर्स अनुमतियाँ**](windows-local-privilege-escalation/#file-and-folder-permissions)
* [ ] [**मेमोरी पासवर्ड माइनिंग**](windows-local-privilege-escalation/#memory-password-mining)
* [ ] [**असुरक्षित GUI ऐप्स**](windows-local-privilege-escalation/#insecure-gui-apps)

### [सेवाएँ](windows-local-privilege-escalation/#services)

* [ ] [क्या आप **किसी भी सेवा को संशोधित कर सकते हैं**?](windows-local-privilege-escalation#permissions)
* [ ] [क्या आप **किसी भी सेवा द्वारा निष्पादित बाइनरी को संशोधित कर सकते हैं**?](windows-local-privilege-escalation/#modify-service-binary-path)
* [ ] [क्या आप **किसी भी सेवा के रजिस्ट्री को संशोधित कर सकते हैं**?](windows-local-privilege-escalation/#services-registry-modify-permissions)
* [ ] [क्या आप **अनुद्धृत सेवा बाइनरी पथ** का लाभ उठा सकते हैं?](windows-local-privilege-escalation/#unquoted-service-paths)

### [**अनुप्रयोग**](windows-local-privilege-escalation/#applications)

* [ ] **लिखित** [**अनुमतियाँ स्थापित अनुप्रयोगों पर**](windows-local-privilege-escalation/#write-permissions)
* [ ] [**स्टार्टअप अनुप्रयोग**](windows-local-privilege-escalation/#run-at-startup)
* [ ] **संवेदनशील** [**ड्राइवर्स**](windows-local-privilege-escalation/#drivers)

### [DLL हाइजैकिंग](windows-local-privilege-escalation/#path-dll-hijacking)

* [ ] क्या आप **PATH के अंदर किसी भी फ़ोल्डर में लिख सकते हैं**?
* [ ] क्या कोई ज्ञात सेवा बाइनरी है जो **किसी अनुपस्थित DLL को लोड करने की कोशिश करती है**?
* [ ] क्या आप **किसी भी बाइनरीज़ फ़ोल्डर में लिख सकते हैं**?

### [नेटवर्क](windows-local-privilege-escalation/#network)

* [ ] नेटवर्क का गणना करें (शेयर्स, इंटरफेस, रूट्स, पड़ोसी, ...)
* [ ] लोकलहोस्ट (127.0.0.1) पर सुनने वाली नेटवर्क सेवाओं पर विशेष ध्यान दें

### [Windows क्रेडेंशियल्स](windows-local-privilege-escalation/#windows-credentials)

* [ ] [**Winlogon** ](windows-local-privilege-escalation/#winlogon-credentials)क्रेडेंशियल्स
* [ ] [**Windows Vault**](windows-local-privilege-escalation/#credentials-manager-windows-vault) क्रेडेंशियल्स जिनका आप उपयोग कर सकते हैं?
* [ ] दिलचस्प [**DPAPI क्रेडेंशियल्स**](windows-local-privilege-escalation/#dpapi)?
* [ ] सहेजे गए [**Wifi नेटवर्क्स**](windows-local-privilege-escalation/#wifi) के पासवर्ड?
* [ ] [**सहेजे गए RDP कनेक्शन्स**](windows-local-privilege-escalation/#saved-rdp-connections) में दिलचस्प जानकारी?
* [ ] [**हाल ही में चलाए गए कमांड्स**](windows-local-privilege-escalation/#recently-run-commands) में पासवर्ड?
* [ ] [**रिमोट डेस्कटॉप क्रेडेंशियल्स मैनेजर**](windows-local-privilege-escalation/#remote-desktop-credential-manager) पासवर्ड?
* [ ] [**AppCmd.exe**](windows-local-privilege-escalation/#appcmd-exe) मौजूद है? क्रेडेंशियल्स?
* [ ] [**SCClient.exe**](windows-local-privilege-escalation/#scclient-sccm)? DLL साइड लोडिंग?

### [फ़ाइलें और रजिस्ट्री (क्रेडेंशियल्स)](windows-local-privilege-escalation/#files-and-registry-credentials)

* [ ] **Putty:** [**क्रेड्स**](windows-local-privilege-escalation/#putty-creds) **और** [**SSH होस्ट कीज़**](windows-local-privilege-escalation/#putty-ssh-host-keys)
* [ ] [**रजिस्ट्री में SSH कीज़**](windows-local-privilege-escalation/#ssh-keys-in-registry)?
* [ ] [**अनटेंडेड फ़ाइलों**](windows-local-privilege-escalation/#unattended-files) में पासवर्ड?
* [ ] कोई [**SAM & SYSTEM**](windows-local-privilege-escalation/#sam-and-system-backups) बैकअप?
* [ ] [**क्लाउड क्रेडेंशियल्स**](windows-local-privilege-escalation/#cloud-credentials)?
* [ ] [**McAfee SiteList.xml**](windows-local-privilege-escalation/#mcafee-sitelist.xml) फ़ा
