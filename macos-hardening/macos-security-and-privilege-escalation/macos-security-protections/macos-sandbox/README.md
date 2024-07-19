# macOS Sandbox

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

## Basic Information

MacOS Sandbox (शुरुआत में Seatbelt कहा जाता था) **सैंडबॉक्स के अंदर चलने वाले अनुप्रयोगों** को **सैंडबॉक्स प्रोफ़ाइल में निर्दिष्ट अनुमत क्रियाओं** तक सीमित करता है जिसके साथ ऐप चल रहा है। यह सुनिश्चित करने में मदद करता है कि **अनुप्रयोग केवल अपेक्षित संसाधनों तक पहुँच रहा होगा**।

कोई भी ऐप जिसमें **अधिकार** **`com.apple.security.app-sandbox`** है, सैंडबॉक्स के अंदर चलाया जाएगा। **एप्पल बाइनरी** आमतौर पर सैंडबॉक्स के अंदर चलाए जाते हैं और **ऐप स्टोर** में प्रकाशित करने के लिए, **यह अधिकार अनिवार्य है**। इसलिए अधिकांश अनुप्रयोग सैंडबॉक्स के अंदर चलाए जाएंगे।

यह नियंत्रित करने के लिए कि एक प्रक्रिया क्या कर सकती है या नहीं कर सकती है, **सैंडबॉक्स में सभी** **syscalls** के लिए **हुक** होते हैं। **ऐप के अधिकारों** के आधार पर, सैंडबॉक्स कुछ क्रियाओं को **अनुमति** देगा।

सैंडबॉक्स के कुछ महत्वपूर्ण घटक हैं:

* **कर्नेल एक्सटेंशन** `/System/Library/Extensions/Sandbox.kext`
* **निजी ढांचा** `/System/Library/PrivateFrameworks/AppSandbox.framework`
* एक **डेमन** जो उपयोगकर्ता भूमि में चल रहा है `/usr/libexec/sandboxd`
* **कंटेनर** `~/Library/Containers`

कंटेनर फ़ोल्डर के अंदर आप **प्रत्येक ऐप के लिए एक फ़ोल्डर पा सकते हैं जो सैंडबॉक्स में चलाया गया है** जिसका नाम बंडल आईडी है:
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
प्रत्येक बंडल आईडी फ़ोल्डर के अंदर आप **plist** और ऐप का **Data directory** पा सकते हैं:
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
ध्यान दें कि भले ही symlinks "Sandbox" से "भागने" और अन्य फ़ोल्डरों तक पहुँचने के लिए हैं, ऐप को अभी भी उन्हें एक्सेस करने के लिए **अनुमतियाँ** होनी चाहिए। ये अनुमतियाँ **`.plist`** के अंदर हैं।
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
एक Sandboxed एप्लिकेशन द्वारा बनाई गई/संशोधित हर चीज़ को **quarantine attribute** मिलेगा। यह **sandbox** स्पेस को Gatekeeper को ट्रिगर करके रोक देगा यदि sandbox ऐप कुछ **`open`** के साथ निष्पादित करने की कोशिश करता है।
{% endhint %}

### Sandbox Profiles

Sandbox प्रोफाइल कॉन्फ़िगरेशन फ़ाइलें हैं जो यह संकेत देती हैं कि उस **Sandbox** में क्या **अनुमति/प्रतिबंधित** होगा। यह **Sandbox Profile Language (SBPL)** का उपयोग करता है, जो [**Scheme**](https://en.wikipedia.org/wiki/Scheme\_\(programming\_language\)) प्रोग्रामिंग भाषा का उपयोग करता है।

यहाँ एक उदाहरण है:
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
Check this [**research**](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/) **यहाँ अधिक क्रियाएँ देखने के लिए जो अनुमति दी जा सकती हैं या अस्वीकृत की जा सकती हैं।**
{% endhint %}

महत्वपूर्ण **सिस्टम सेवाएँ** अपने स्वयं के कस्टम **सैंडबॉक्स** के अंदर चलती हैं जैसे कि `mdnsresponder` सेवा। आप इन कस्टम **सैंडबॉक्स प्रोफाइल** को देख सकते हैं:

* **`/usr/share/sandbox`**
* **`/System/Library/Sandbox/Profiles`**&#x20;
* अन्य सैंडबॉक्स प्रोफाइल को [https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles](https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles) पर चेक किया जा सकता है।

**ऐप स्टोर** ऐप्स **प्रोफाइल** **`/System/Library/Sandbox/Profiles/application.sb`** का उपयोग करते हैं। आप इस प्रोफाइल में देख सकते हैं कि कैसे अधिकार जैसे **`com.apple.security.network.server`** एक प्रक्रिया को नेटवर्क का उपयोग करने की अनुमति देते हैं।

SIP एक सैंडबॉक्स प्रोफाइल है जिसे /System/Library/Sandbox/rootless.conf में platform\_profile कहा जाता है।

### सैंडबॉक्स प्रोफाइल उदाहरण

एक **विशिष्ट सैंडबॉक्स प्रोफाइल** के साथ एक एप्लिकेशन शुरू करने के लिए आप उपयोग कर सकते हैं:
```bash
sandbox-exec -f example.sb /Path/To/The/Application
```
{% tabs %}
{% tab title="touch" %}
{% code title="touch.sb" %}
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
ध्यान दें कि **Apple द्वारा लिखित** **सॉफ़्टवेयर** जो **Windows** पर चलता है, उसमें **अतिरिक्त सुरक्षा उपाय** नहीं हैं, जैसे कि एप्लिकेशन सैंडबॉक्सिंग।
{% endhint %}

बायपास के उदाहरण:

* [https://lapcatsoftware.com/articles/sandbox-escape.html](https://lapcatsoftware.com/articles/sandbox-escape.html)
* [https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c) (वे `~$` से शुरू होने वाले नाम के साथ सैंडबॉक्स के बाहर फ़ाइलें लिखने में सक्षम हैं)।

### MacOS सैंडबॉक्स प्रोफाइल

macOS सिस्टम सैंडबॉक्स प्रोफाइल को दो स्थानों पर संग्रहीत करता है: **/usr/share/sandbox/** और **/System/Library/Sandbox/Profiles**।

और यदि कोई तृतीय-पक्ष एप्लिकेशन _**com.apple.security.app-sandbox**_ अधिकार रखता है, तो सिस्टम उस प्रक्रिया पर **/System/Library/Sandbox/Profiles/application.sb** प्रोफाइल लागू करता है।

### **iOS सैंडबॉक्स प्रोफाइल**

डिफ़ॉल्ट प्रोफाइल को **container** कहा जाता है और हमारे पास SBPL पाठ प्रतिनिधित्व नहीं है। मेमोरी में, इस सैंडबॉक्स को सैंडबॉक्स से प्रत्येक अनुमति के लिए Allow/Deny बाइनरी ट्री के रूप में दर्शाया गया है।

### डिबग और बायपास सैंडबॉक्स

macOS पर, iOS के विपरीत जहां प्रक्रियाएँ शुरू से ही कर्नेल द्वारा सैंडबॉक्स की जाती हैं, **प्रक्रियाओं को स्वयं सैंडबॉक्स में शामिल होना चाहिए**। इसका मतलब है कि macOS पर, एक प्रक्रिया तब तक सैंडबॉक्स द्वारा प्रतिबंधित नहीं होती जब तक कि वह सक्रिय रूप से इसमें प्रवेश करने का निर्णय नहीं लेती।

यदि प्रक्रियाओं के पास अधिकार है: `com.apple.security.app-sandbox`, तो वे उपयोगकर्ता भूमि से स्वचालित रूप से सैंडबॉक्स की जाती हैं जब वे शुरू होती हैं। इस प्रक्रिया के विस्तृत विवरण के लिए देखें:

{% content-ref url="macos-sandbox-debug-and-bypass/" %}
[macos-sandbox-debug-and-bypass](macos-sandbox-debug-and-bypass/)
{% endcontent-ref %}

### **PID विशेषाधिकार जांचें**

[**इसके अनुसार**](https://www.youtube.com/watch?v=mG715HcDgO8\&t=3011s), **`sandbox_check`** (यह एक `__mac_syscall` है), यह जांच सकता है **कि किसी ऑपरेशन की अनुमति है या नहीं** किसी निश्चित PID द्वारा सैंडबॉक्स में।

[**उपकरण sbtool**](http://newosxbook.com/src.jl?tree=listings\&file=sbtool.c) यह जांच सकता है कि क्या एक PID एक निश्चित क्रिया कर सकता है:
```bash
sbtool <pid> mach #Check mac-ports (got from launchd with an api)
sbtool <pid> file /tmp #Check file access
sbtool <pid> inspect #Gives you an explaination of the sandbox profile
sbtool <pid> all
```
### Custom SBPL in App Store apps

यह संभव है कि कंपनियाँ अपने ऐप्स को **कस्टम सैंडबॉक्स प्रोफाइल** के साथ चलाएँ (डिफ़ॉल्ट प्रोफाइल के बजाय)। उन्हें एप्पल द्वारा अधिकृत **`com.apple.security.temporary-exception.sbpl`** अधिकार का उपयोग करने की आवश्यकता है।

इस अधिकार की परिभाषा की जाँच करना संभव है **`/System/Library/Sandbox/Profiles/application.sb:`**
```scheme
(sandbox-array-entitlement
"com.apple.security.temporary-exception.sbpl"
(lambda (string)
(let* ((port (open-input-string string)) (sbpl (read port)))
(with-transparent-redirection (eval sbpl)))))
```
यह **इस अधिकार के बाद के स्ट्रिंग को** एक Sandbox प्रोफ़ाइल के रूप में **eval** करेगा।

{% hint style="success" %}
सीखें और AWS हैकिंग का अभ्यास करें:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
सीखें और GCP हैकिंग का अभ्यास करें: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks का समर्थन करें</summary>

* [**सदस्यता योजनाएँ**](https://github.com/sponsors/carlospolop) देखें!
* **हमारे** 💬 [**Discord समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) में शामिल हों या **हमारे** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** का पालन करें।**
* **हैकिंग ट्रिक्स साझा करें और** [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) गिटहब रिपोजिटरी में PRs सबमिट करें।

</details>
{% endhint %}
