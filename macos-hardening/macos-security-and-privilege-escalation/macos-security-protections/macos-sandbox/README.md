# macOS सैंडबॉक्स

<details>

<summary><strong>जानें AWS हैकिंग को शून्य से हीरो तक</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> के साथ!</strong></summary>

HackTricks का समर्थन करने के अन्य तरीके:

* यदि आप अपनी **कंपनी का विज्ञापन HackTricks में देखना चाहते हैं** या **HackTricks को PDF में डाउनलोड करना चाहते हैं** तो [**सब्सक्रिप्शन प्लान्स देखें**](https://github.com/sponsors/carlospolop)!
* [**आधिकारिक PEASS और HackTricks स्वैग**](https://peass.creator-spring.com) प्राप्त करें
* हमारे विशेष [**NFTs**](https://opensea.io/collection/the-peass-family) संग्रह [**The PEASS Family**](https://opensea.io/collection/the-peass-family) खोजें
* **शामिल हों** 💬 [**डिस्कॉर्ड समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) या हमें **ट्विटर** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)** पर फॉलो** करें।
* **हैकिंग ट्रिक्स साझा करें** द्वारा **PR जमा करके** [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos में।

</details>

## मूल जानकारी

MacOS सैंडबॉक्स (पहले सीटबेल्ट कहा जाता था) **सैंडबॉक्स प्रोफ़ाइल में निर्दिष्ट अनुमत क्रियाओं तक सीमित करता है** जिसमें ऐप चल रहा है। यह सुनिश्चित करने में मदद करता है कि **ऐप्लिकेशन केवल अपेक्षित संसाधनों तक ही पहुंचेगा**।

किसी भी ऐप में **अधिकार** **`com.apple.security.app-sandbox`** होगा तो सैंडबॉक्स में चलाया जाएगा। **एप्पल बाइनरी** आम तौर पर सैंडबॉक्स में चलाए जाते हैं और **एप्प स्टोर** में प्रकाशित करने के लिए **यह अधिकार अनिवार्य है**। इसलिए अधिकांश ऐप्लिकेशन सैंडबॉक्स में चलाए जाएंगे।

प्रक्रिया को क्या करने या क्या नहीं करने देने के लिए **सैंडबॉक्स में हुक्स** होते हैं सभी **कर्नेल** के सभी **सिसकॉल्स** में। ऐप के **अधिकारों** के आधार पर सैंडबॉक्स कुछ क्रियाएँ **अनुमति** देगा।

सैंडबॉक्स के कुछ महत्वपूर्ण घटक हैं:

* **कर्नेल एक्सटेंशन** `/System/Library/Extensions/Sandbox.kext`
* **निजी फ्रेमवर्क** `/System/Library/PrivateFrameworks/AppSandbox.framework`
* एक **डेमन** जो यूजरलैंड में चल रहा है `/usr/libexec/sandboxd`
* **कंटेनर** `~/Library/Containers`

कंटेनर्स फ़ोल्डर के अंदर आप **हर ऐप के लिए एक फ़ोल्डर पाएंगे जो सैंडबॉक्स में चलाया गया है** जिसका नाम है bundle id:
```bash
ls -l ~/Library/Containers
total 0
drwx------@ 4 username  staff  128 May 23 20:20 com.apple.AMPArtworkAgent
drwx------@ 4 username  staff  128 May 23 20:13 com.apple.AMPDeviceDiscoveryAgent
drwx------@ 4 username  staff  128 Mar 24 18:03 com.apple.AVConference.Diagnostic
drwx------@ 4 username  staff  128 Mar 25 14:14 com.apple.Accessibility-Settings.extension
drwx------@ 4 username  staff  128 Mar 25 14:10 com.apple.ActionKit.BundledIntentHandler
[...]
```
हर बंडल आईडी फ़ोल्डर में आप ऐप का **plist** और **डेटा डायरेक्टरी** पा सकते हैं:
```bash
cd /Users/username/Library/Containers/com.apple.Safari
ls -la
total 104
drwx------@   4 username  staff    128 Mar 24 18:08 .
drwx------  348 username  staff  11136 May 23 20:57 ..
-rw-r--r--    1 username  staff  50214 Mar 24 18:08 .com.apple.containermanagerd.metadata.plist
drwx------   13 username  staff    416 Mar 24 18:05 Data

ls -l Data
total 0
drwxr-xr-x@  8 username  staff   256 Mar 24 18:08 CloudKit
lrwxr-xr-x   1 username  staff    19 Mar 24 18:02 Desktop -> ../../../../Desktop
drwx------   2 username  staff    64 Mar 24 18:02 Documents
lrwxr-xr-x   1 username  staff    21 Mar 24 18:02 Downloads -> ../../../../Downloads
drwx------  35 username  staff  1120 Mar 24 18:08 Library
lrwxr-xr-x   1 username  staff    18 Mar 24 18:02 Movies -> ../../../../Movies
lrwxr-xr-x   1 username  staff    17 Mar 24 18:02 Music -> ../../../../Music
lrwxr-xr-x   1 username  staff    20 Mar 24 18:02 Pictures -> ../../../../Pictures
drwx------   2 username  staff    64 Mar 24 18:02 SystemData
drwx------   2 username  staff    64 Mar 24 18:02 tmp
```
{% hint style="danger" %}
ध्यान दें कि यदि सिमलिंक्स सैंडबॉक्स से "बाहर निकलने" और अन्य फ़ोल्डर तक पहुंचने के लिए मौजूद हैं, तो भी ऐप को उन तक पहुंचने की अनुमति होनी चाहिए। ये अनुमतियाँ **`.plist`** में होती हैं।
{% endhint %}
```bash
# Get permissions
plutil -convert xml1 .com.apple.containermanagerd.metadata.plist -o -

# Binary sandbox profile
<key>SandboxProfileData</key>
<data>
AAAhAboBAAAAAAgAAABZAO4B5AHjBMkEQAUPBSsGPwsgASABHgEgASABHwEf...

# In this file you can find the entitlements:
<key>Entitlements</key>
<dict>
<key>com.apple.MobileAsset.PhishingImageClassifier2</key>
<true/>
<key>com.apple.accounts.appleaccount.fullaccess</key>
<true/>
<key>com.apple.appattest.spi</key>
<true/>
<key>keychain-access-groups</key>
<array>
<string>6N38VWS5BX.ru.keepcoder.Telegram</string>
<string>6N38VWS5BX.ru.keepcoder.TelegramShare</string>
</array>
[...]

# Some parameters
<key>Parameters</key>
<dict>
<key>_HOME</key>
<string>/Users/username</string>
<key>_UID</key>
<string>501</string>
<key>_USER</key>
<string>username</string>
[...]

# The paths it can access
<key>RedirectablePaths</key>
<array>
<string>/Users/username/Downloads</string>
<string>/Users/username/Documents</string>
<string>/Users/username/Library/Calendars</string>
<string>/Users/username/Desktop</string>
<key>RedirectedPaths</key>
<array/>
[...]
```
{% hint style="warning" %}
सैंडबॉक्स एप्लिकेशन द्वारा बनाए या संशोधित किया गया हर वस्तु **क्वारंटाइन एट्रिब्यूट** प्राप्त करेगी। यह सैंडबॉक्स ऐप्लिकेशन को रोकेगा अगर सैंडबॉक्स एप्लिकेशन को **`open`** के साथ कुछ निष्पादित करने की कोशिश करता है।
{% endhint %}

### सैंडबॉक्स प्रोफाइल

सैंडबॉक्स प्रोफाइल कॉन्फ़िगरेशन फ़ाइलें हैं जो इस सैंडबॉक्स में क्या **अनुमति/निषेधित** होने वाला है वह दिखाती है। यह **सैंडबॉक्स प्रोफ़ाइल भाषा (SBPL)** का उपयोग करती है, जो [**स्कीम**](https://en.wikipedia.org/wiki/Scheme\_\(programming\_language\)) प्रोग्रामिंग भाषा का उपयोग करती है।

यहाँ आप एक उदाहरण पा सकते हैं:
```scheme
(version 1) ; First you get the version

(deny default) ; Then you shuold indicate the default action when no rule applies

(allow network*) ; You can use wildcards and allow everything

(allow file-read* ; You can specify where to apply the rule
(subpath "/Users/username/")
(literal "/tmp/afile")
(regex #"^/private/etc/.*")
)

(allow mach-lookup
(global-name "com.apple.analyticsd")
)
```
{% hint style="success" %}
इस [**शोध**](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/) **की जाँच करें और अधिक क्रियाएँ जो अनुमति दी जा सकती हैं या नहीं।**
{% endhint %}

महत्वपूर्ण **सिस्टम सेवाएं** भी अपने खुद के **संदूक** में चलती हैं जैसे `mdnsresponder` सेवा। आप इन विशेष **सैंडबॉक्स प्रोफाइल** को निम्नलिखित में देख सकते हैं:

* **`/usr/share/sandbox`**
* **`/System/Library/Sandbox/Profiles`**&#x20;
* अन्य सैंडबॉक्स प्रोफाइल यहाँ देखे जा सकते हैं [https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles](https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles).

**ऐप स्टोर** ऐप्स **प्रोफाइल** का उपयोग करते हैं **`/System/Library/Sandbox/Profiles/application.sb`**। आप इस प्रोफाइल में देख सकते हैं कि कैसे **`com.apple.security.network.server`** जैसे अधिकारों द्वारा प्रक्रिया को नेटवर्क का उपयोग करने की अनुमति देता है।

SIP एक सैंडबॉक्स प्रोफाइल है जिसे platform\_profile कहा जाता है /System/Library/Sandbox/rootless.conf

### सैंडबॉक्स प्रोफाइल उदाहरण

एक **निश्चित सैंडबॉक्स प्रोफाइल** के साथ एक ऐप्लिकेशन शुरू करने के लिए आप इस्तेमाल कर सकते हैं:
```bash
sandbox-exec -f example.sb /Path/To/The/Application
```
{% tabs %}
{% tab title="स्पर्श" %}
{% code title="स्पर्श.sb" %}
```scheme
(version 1)
(deny default)
(allow file* (literal "/tmp/hacktricks.txt"))
```
{% endcode %}
```bash
# This will fail because default is denied, so it cannot execute touch
sandbox-exec -f touch.sb touch /tmp/hacktricks.txt
# Check logs
log show --style syslog --predicate 'eventMessage contains[c] "sandbox"' --last 30s
[...]
2023-05-26 13:42:44.136082+0200  localhost kernel[0]: (Sandbox) Sandbox: sandbox-exec(41398) deny(1) process-exec* /usr/bin/touch
2023-05-26 13:42:44.136100+0200  localhost kernel[0]: (Sandbox) Sandbox: sandbox-exec(41398) deny(1) file-read-metadata /usr/bin/touch
2023-05-26 13:42:44.136321+0200  localhost kernel[0]: (Sandbox) Sandbox: sandbox-exec(41398) deny(1) file-read-metadata /var
2023-05-26 13:42:52.701382+0200  localhost kernel[0]: (Sandbox) 5 duplicate reports for Sandbox: sandbox-exec(41398) deny(1) file-read-metadata /var
[...]
```
{% code title="touch2.sb" %}
```scheme
(version 1)
(deny default)
(allow file* (literal "/tmp/hacktricks.txt"))
(allow process* (literal "/usr/bin/touch"))
; This will also fail because:
; 2023-05-26 13:44:59.840002+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-metadata /usr/bin/touch
; 2023-05-26 13:44:59.840016+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-data /usr/bin/touch
; 2023-05-26 13:44:59.840028+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-data /usr/bin
; 2023-05-26 13:44:59.840034+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-metadata /usr/lib/dyld
; 2023-05-26 13:44:59.840050+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) sysctl-read kern.bootargs
; 2023-05-26 13:44:59.840061+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-data /
```
{% endcode %}

{% code title="touch3.sb" %}
```scheme
(version 1)
(deny default)
(allow file* (literal "/private/tmp/hacktricks.txt"))
(allow process* (literal "/usr/bin/touch"))
(allow file-read-data (literal "/"))
; This one will work
```
{% endcode %}
{% endtab %}
{% endtabs %}

{% hint style="info" %}
ध्यान दें कि **Windows पर चलने वाले Apple द्वारा बनाए गए सॉफ्टवेयर** में अतिरिक्त सुरक्षा सावधानियाँ नहीं हैं, जैसे कि एप्लिकेशन सैंडबॉक्सिंग।
{% endhint %}

बायपास उदाहरण:

* [https://lapcatsoftware.com/articles/sandbox-escape.html](https://lapcatsoftware.com/articles/sandbox-escape.html)
* [https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c) (वे `~$` से शुरू होने वाले सैंडबॉक्स के बाहर फ़ाइलें लिख सकते हैं)।

### MacOS सैंडबॉक्स प्रोफाइल

macOS सिस्टम सैंडबॉक्स प्रोफाइल को दो स्थानों में संग्रहित करता है: **/usr/share/sandbox/** और **/System/Library/Sandbox/Profiles**।

और अगर किसी थर्ड-पार्टी एप्लिकेशन में _**com.apple.security.app-sandbox**_ अधिकार है, तो सिस्टम **/System/Library/Sandbox/Profiles/application.sb** प्रोफाइल को उस प्रक्रिया पर लागू करता है।

### **iOS सैंडबॉक्स प्रोफाइल**

डिफ़ॉल्ट प्रोफ़ाइल को **कंटेनर** कहा जाता है और हमें SBPL पाठ प्रतिनिधित्व नहीं है। मेमोरी में, यह सैंडबॉक्स प्रत्येक अनुमतियों के लिए Allow/Deny बाइनरी ट्री के रूप में प्रतिनिधित्व किया जाता है।

### डीबग और सैंडबॉक्स को बायपास करें

macOS पर, iOS की तरह जहां प्रक्रियाएँ कर्नेल द्वारा प्रारंभ में सैंडबॉक्स में होती हैं, **प्रक्रियाएँ स्वयं सैंडबॉक्स में शामिल होने के लिए विकल्प चुनना होता है**। इसका मतलब है कि macOS पर, एक प्रक्रिया सैंडबॉक्स द्वारा प्रतिबंधित नहीं है जब तक वह इसमें प्रवेश करने का सक्रिय रूप से निर्णय नहीं लेती।

प्रक्रियाएँ उस समय स्वचालित रूप से सैंडबॉक्स में बंद हो जाती हैं जब वे शुरू होती हैं अगर उनके पास यह अधिकार है: `com.apple.security.app-sandbox`। इस प्रक्रिया का विस्तृत विवरण के लिए देखें:

{% content-ref url="macos-sandbox-debug-and-bypass/" %}
[macos-sandbox-debug-and-bypass](macos-sandbox-debug-and-bypass/)
{% endcontent-ref %}

### **PID विशेषाधिकार जांचें**

[**इस के अनुसार**](https://www.youtube.com/watch?v=mG715HcDgO8\&t=3011s), **`sandbox_check`** (यह एक `__mac_syscall` है), किसी निश्चित PID में सैंडबॉक्स द्वारा किसी कार्रवाई की अनुमति है या नहीं यह जांच सकता है।

[**उपकरण sbtool**](http://newosxbook.com/src.jl?tree=listings\&file=sbtool.c) यह जांच सकता है कि क्या एक PID किसी विशिष्ट कार्रवाई को कर सकता है:
```bash
sbtool <pid> mach #Check mac-ports (got from launchd with an api)
sbtool <pid> file /tmp #Check file access
sbtool <pid> inspect #Gives you an explaination of the sandbox profile
sbtool <pid> all
```
### App Store ऐप्स में कस्टम SBPL

कंपनियों के लिए अपने ऐप्स को **कस्टम सैंडबॉक्स प्रोफाइल्स** के साथ चलाना संभव हो सकता है (डिफ़ॉल्ट वाले के बजाय). उन्हें **`com.apple.security.temporary-exception.sbpl`** इंटाइटलमेंट का उपयोग करना होगा जिसे Apple द्वारा अधिकृत किया जाना चाहिए।

इस इंटाइटलमेंट की परिभाषा की जांच **`/System/Library/Sandbox/Profiles/application.sb:`** में संभव है।
```scheme
(sandbox-array-entitlement
"com.apple.security.temporary-exception.sbpl"
(lambda (string)
(let* ((port (open-input-string string)) (sbpl (read port)))
(with-transparent-redirection (eval sbpl)))))
```
यह **इस entitlement के बाद दिए गए स्ट्रिंग को** एक Sandbox प्रोफ़ाइल के रूप में evaluate करेगा।

<details>

<summary><strong>जानें AWS हैकिंग को शून्य से हीरो तक</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> के साथ</strong>!</summary>

HackTricks का समर्थन करने के अन्य तरीके:

* अगर आप अपनी **कंपनी का विज्ञापन HackTricks में देखना चाहते हैं** या **HackTricks को PDF में डाउनलोड करना चाहते हैं** तो [**सब्सक्रिप्शन प्लान्स**](https://github.com/sponsors/carlospolop) देखें!
* [**आधिकारिक PEASS & HackTricks swag**](https://peass.creator-spring.com) प्राप्त करें
* हमारे विशेष [**NFTs**](https://opensea.io/collection/the-peass-family) कलेक्शन, [**The PEASS Family**](https://opensea.io/collection/the-peass-family) खोजें
* **शामिल हों** 💬 [**Discord समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) या हमें **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live) **पर फ़ॉलो** करें।
* **अपने हैकिंग ट्रिक्स साझा करें, HackTricks** और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos में PRs सबमिट करके।

</details>
