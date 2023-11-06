# चेकलिस्ट - स्थानीय Windows विशेषाधिकार उन्नयन

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- क्या आप किसी **साइबर सुरक्षा कंपनी** में काम करते हैं? क्या आप अपनी कंपनी को **HackTricks में विज्ञापित** देखना चाहते हैं? या क्या आपको **PEASS के नवीनतम संस्करण या HackTricks को PDF में डाउनलोड करने का उपयोग** करने की आवश्यकता है? [**सदस्यता योजनाएं**](https://github.com/sponsors/carlospolop) की जांच करें!

- [**The PEASS Family**](https://opensea.io/collection/the-peass-family) की खोज करें, हमारा विशेष संग्रह [**NFTs**](https://opensea.io/collection/the-peass-family)

- [**आधिकारिक PEASS और HackTricks swag**](https://peass.creator-spring.com) प्राप्त करें

- [**💬**](https://emojipedia.org/speech-balloon/) [**Discord समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) में **शामिल हों** या मुझे **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)** का पालन करें**.

- **अपने हैकिंग ट्रिक्स को [hacktricks रेपो](https://github.com/carlospolop/hacktricks) और [hacktricks-cloud रेपो](https://github.com/carlospolop/hacktricks-cloud) में पीआर जमा करके साझा करें**.

</details>

### **Windows स्थानीय विशेषाधिकार उन्नयन के लिए सर्वश्रेष्ठ टूल:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [सिस्टम जानकारी](windows-local-privilege-escalation/#system-info)

* [ ] [**सिस्टम जानकारी**](windows-local-privilege-escalation/#system-info) प्राप्त करें
* [ ] स्क्रिप्ट का उपयोग करके **कर्नल** [**शोधें**](windows-local-privilege-escalation/#version-exploits)
* [ ] कर्नल **शोधन** के लिए **Google का उपयोग करें**
* [ ] कर्नल **शोधन** के लिए **searchsploit का उपयोग करें**
* [ ] [**एनवायरनमेंट वेर्स**](windows-local-privilege-escalation/#environment) में दिलचस्प जानकारी?
* [ ] [**PowerShell इतिहास**](windows-local-privilege-escalation/#powershell-history) में पासवर्ड?
* [ ] [**इंटरनेट सेटिंग्स**](windows-local-privilege-escalation/#internet-settings) में दिलचस्प जानकारी?
* [ ] [**ड्राइव्स**](windows-local-privilege-escalation/#drives)?
* [ ] [**WSUS उत्पीड़न**](windows-local-privilege-escalation/#wsus)?
* [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/#alwaysinstallelevated)?

### [लॉगिंग/AV जाँच](windows-local-privilege-escalation/#enumeration)

* [ ] [**नीति**](windows-local-privilege-escalation/#audit-settings) और [**WEF**](windows-local-privilege-escalation/#wef) सेटिंग्स जाँचें
* [ ] [**LAPS**](windows-local-privilege-escalation/#laps) जाँचें
* [ ] क्या [**WDigest**](windows-local-privilege-escalation/#wdigest) सक्रिय है?
* [ ] [**LSA संरक्षण**](windows-local-privilege-escalation/#lsa-protection)?
* [ ] [**क्रेडेंशियल्स गार्ड**](windows-local-privilege-escalation/#credentials-guard)[?](windows-local-privilege-escalation/#cached-credentials)
* [ ] [**कैश्ड क्रेडेंशियल्स**](windows-local-privilege-escalation/#cached-credentials)?
* [ ] क्या कोई [**AV**](windows-av-bypass) है?
* [ ] [**AppLocker नीति**](authentication-credentials-uac-and-efs#applocker-policy)?
* [ ] [**UAC**](authentication-credentials-uac-and-efs/uac-user-account-control)?
* [ ] [**उपयोगकर्ता विशेषाधिकार**](windows-local-privilege-escalation/#users-and-groups)?
* [ ] [**वर्तमान** उपयोगकर्ता **विशेषाधिकार**](windows-local-privilege-escalation/#users-and-groups) जाँचें
* [ ] क्या आप [**किसी विशेषाधिकृत समूह के सदस्य**](windows-local-privilege-escalation/#privileged-groups) हैं?
* [ ] क्या आपके पास इनमें से कोई भी टोकन सक्षम हैं: **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege**?
* [ ] [**उपयोगकर्ता सत्र**](windows-local-privilege-escalation/#logged-users-sessions)?
* [ ] [**उपयोगकर्ता होम**](windows-local-privilege-escalation/#home-folders) जाँचें (पहुँच?)
* [ ] [**पासवर्ड नीति**](windows-local-privilege-escalation/#password-policy) जाँचें
* [ ] [**क्लिपबोर्ड में क्या है**](windows-local-privilege-escalation/#get-the-content-of-the-clipboard)?

### [नेटवर्क](windows-local-privilege-escalation/#network)

* [ ] [**वर्तमान** **नेटवर्क** **जानकारी**](windows-local-privilege-escalation/#network) जाँचें
* [ ] बाहरी तक सीमित **छिपी हुई स्थानीय सेवाएं** जाँचें

### [चल रहे प्रक्रियाएं](windows-local-privilege-escalation/#running-processes)

* [ ] प्रक्रिया बाइनरी [**फ़ाइल और फ़ोल्डर अनुमतियाँ**](windows-local-privilege-escalation/#file-and-folder-permissions) जाँचें
* [ ] [**मेमोरी पासवर्ड खनन**](windows-local-privilege-escalation/#memory-password-mining)
* [ ] [**असुरक्षित GUI ऐप्स**](windows-local-privilege-escalation
### [सेवाएं](windows-local-privilege-escalation/#services)

* [ ] क्या आप किसी सेवा को **संशोधित** कर सकते हैं?
* [ ] क्या आप किसी सेवा द्वारा **चलाए जाने वाले** **बाइनरी** को **संशोधित** कर सकते हैं?
* [ ] क्या आप किसी सेवा के **रजिस्ट्री** को **संशोधित** कर सकते हैं?
* [ ] क्या आप किसी **अनदेखी सेवा** बाइनरी **पथ** का लाभ उठा सकते हैं?

### [**अनुप्रयोग**](windows-local-privilege-escalation/#applications)

* [ ] **स्थापित अनुप्रयोगों** पर **लेखन** **अनुमतियाँ**
* [ ] [**स्टार्टअप अनुप्रयोग**](windows-local-privilege-escalation/#run-at-startup)
* [ ] **वंशज** [**ड्राइवर**](windows-local-privilege-escalation/#drivers)

### [DLL हाइजैकिंग](windows-local-privilege-escalation/#path-dll-hijacking)

* [ ] क्या आप **पाथ** के भीतर किसी भी फ़ोल्डर में **लिख सकते** हैं?
* [ ] क्या कोई ज्ञात सेवा बाइनरी है जो किसी अस्तित्व रहित DLL को लोड करने का प्रयास करती है?
* [ ] क्या आप किसी **बाइनरी फ़ोल्डर** में **लिख सकते** हैं?

### [नेटवर्क](windows-local-privilege-escalation/#network)

* [ ] नेटवर्क की जांच करें (शेयर, इंटरफ़ेस, रूट, पड़ोसी, ...)
* [ ] लोकलहोस्ट (127.0.0.1) पर सुनने वाली नेटवर्क सेवाओं पर विशेष ध्यान दें

### [Windows क्रेडेंशियल](windows-local-privilege-escalation/#windows-credentials)

* [ ] [**Winlogon**](windows-local-privilege-escalation/#winlogon-credentials) क्रेडेंशियल
* [ ] [**Windows Vault**](windows-local-privilege-escalation/#credentials-manager-windows-vault) क्रेडेंशियल जिन्हें आप उपयोग कर सकते हैं?
* [ ] रोचक [**DPAPI क्रेडेंशियल**](windows-local-privilege-escalation/#dpapi)?
* [ ] सहेजे गए [**वाईफ़ाई नेटवर्क**](windows-local-privilege-escalation/#wifi) के पासवर्ड?
* [ ] [**सहेजे गए RDP कनेक्शन**](windows-local-privilege-escalation/#saved-rdp-connections) में रोचक जानकारी?
* [ ] हाल ही में चलाए गए कमांड्स में पासवर्ड?
* [ ] [**रिमोट डेस्कटॉप क्रेडेंशियल मैनेजर**](windows-local-privilege-escalation/#remote-desktop-credential-manager) पासवर्ड?
* [**AppCmd.exe मौजूद**](windows-local-privilege-escalation/#appcmd-exe)? क्रेडेंशियल?
* [ ] [**SCClient.exe**](windows-local-privilege-escalation/#scclient-sccm)? DLL साइड लोडिंग?

### [फ़ाइल और रजिस्ट्री (क्रेडेंशियल)](windows-local-privilege-escalation/#files-and-registry-credentials)

* [ ] **Putty:** [**क्रेडेंशियल**](windows-local-privilege-escalation/#putty-creds) और [**SSH होस्ट कुंजी**](windows-local-privilege-escalation/#putty-ssh-host-keys)
* [ ] [**रजिस्ट्री में SSH कुंजी**](windows-local-privilege-escalation/#ssh-keys-in-registry)?
* [ ] [**अनटेंडेड फ़ाइल्स**](windows-local-privilege-escalation/#unattended-files) में पासवर्ड?
* [ ] कोई [**SAM और SYSTEM**](windows-local-privilege-escalation/#sam-and-system-backups) बैकअप?
* [ ] [**क्लाउड क्रेडेंशियल**](windows-local-privilege-escalation/#cloud-credentials)?
* [ ] [**McAfee SiteList.xml**](windows-local-privilege-escalation/#mcafee-sitelist.xml) फ़ाइल?
* [ ] [**कैश्ड GPP पासवर्ड**](windows-local-privilege-escalation/#cached-gpp-pasword)?
* [ ] [**IIS वेब कॉन्फ़िग फ़ाइल**](windows-local-privilege-escalation/#iis-web-config) में पासवर्ड?
* [ ] [**वेब लॉग**](windows-local-privilege-escalation/#logs) में रोचक जानकारी?
* [ ] क्या आप **उपयोगकर्ता से क्रेडेंशियल** मांगना चाहते हैं?
* [ ] [**रीसायकल बिन में रोचक फ़ाइलें**](windows-local-privilege-escalation/#credentials-in-the-recyclebin)?
* [ ] अन्य [**क्रेडेंशियल युक्त रजिस्ट्री**](windows-local-privilege-escalation/#inside-the-registry)?
* [ ] [**ब्राउज़र डेटा**](windows-local-privilege-escalation/#browsers-history) में (डीबी, इतिहास, बुकमार्क्स, ...)?
* [ ] फ़ाइलों और रजिस्ट्री में [**सामान्य पासवर्ड खोज**](windows-local-privilege-escalation/#generic-password-search-in-files-and-registry)?
* [ ] पासवर्ड खोज के लिए [**टूल**](windows-local-privilege-escalation/#tools-that-search-for-passwords)?

### [लीक हैंडलर](windows-local-privilege-escalation/#leaked-handlers)

* [ ] क्या आपके पास व्यवस्थापक द्वारा चलाए गए किसी प्रक्रिया के हैंडलर तक पहुंच है?

### [पाइप क्लाइंट अनुकरण](windows-local-privilege-escalation/#named-pipe-client-impersonation)

* [ ] क्या आप इसका दुरुपयोग कर सकते हैं?

<details>

<summary><a href="https
