# macOS IOKit

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* क्या आप **साइबर सुरक्षा कंपनी** में काम कर रहे हैं? क्या आप अपनी **कंपनी को हैकट्रिक्स में विज्ञापित करना चाहते हैं**? या आप **PEASS की नवीनतम संस्करण देखना चाहते हैं या HackTricks को PDF में डाउनलोड करना चाहते हैं**? तो [**सदस्यता की योजनाएं देखें**](https://github.com/sponsors/carlospolop)!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) की खास [**NFTs**](https://opensea.io/collection/the-peass-family) कलेक्शन को खोजें
* [**PEASS और HackTricks के आधिकारिक स्वैग**](https://peass.creator-spring.com) प्राप्त करें
* **डिस्कॉर्ड** [**💬**](https://emojipedia.org/speech-balloon/) **समूह** या **टेलीग्राम समूह** में **शामिल हों** या **मुझे** **ट्विटर** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live) **पर फॉलो करें**.
* **हैकिंग ट्रिक्स को साझा करें** [**hacktricks रेपो**](https://github.com/carlospolop/hacktricks) **और** [**hacktricks-cloud रेपो**](https://github.com/carlospolop/hacktricks-cloud) **में पीआर भेजकर**.

</details>

## मूल जानकारी

I/O Kit एक ओपन-सोर्स, ऑब्ज
```bash
# Get demangled symbols
nm -C com.apple.driver.AppleJPEGDriver

# Demangled symbols from stdin
c++filt
__ZN16IOUserClient202222dispatchExternalMethodEjP31IOExternalMethodArgumentsOpaquePK28IOExternalMethodDispatch2022mP8OSObjectPv
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
{% hint style="danger" %}
IOKit **उजागर कार्य** जब कोई क्लाइंट किसी फ़ंक्शन को कॉल करने की कोशिश करता है, तो **अतिरिक्त सुरक्षा जांचें** कर सकता है, लेकिन ध्यान दें कि एप्स आम तौर पर **सैंडबॉक्स** द्वारा **सीमित** होते हैं कि IOKit फ़ंक्शन के साथ वे किस प्रकार से बातचीत कर सकते हैं।
{% endhint %}

## ड्राइवर

macOS में वे यहाँ स्थित हैं:

* **`/System/Library/Extensions`**
* OS X ऑपरेटिंग सिस्टम में बिल्ट इन KEXT फ़ाइलें।
* **`/Library/Extensions`**
* 3rd पार्टी सॉफ़्टवेयर द्वारा स्थापित KEXT फ़ाइलें

iOS में वे यहाँ स्थित हैं:

* **`/System/Library/Extensions`**
```bash
#Use kextstat to print the loaded drivers
kextstat
Executing: /usr/bin/kmutil showloaded
No variant specified, falling back to release
Index Refs Address            Size       Wired      Name (Version) UUID <Linked Against>
1  142 0                  0          0          com.apple.kpi.bsd (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
2   11 0                  0          0          com.apple.kpi.dsep (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
3  170 0                  0          0          com.apple.kpi.iokit (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
4    0 0                  0          0          com.apple.kpi.kasan (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
5  175 0                  0          0          com.apple.kpi.libkern (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
6  154 0                  0          0          com.apple.kpi.mach (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
7   88 0                  0          0          com.apple.kpi.private (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
8  106 0                  0          0          com.apple.kpi.unsupported (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
9    2 0xffffff8003317000 0xe000     0xe000     com.apple.kec.Libm (1) 6C1342CC-1D74-3D0F-BC43-97D5AD38200A <5>
10   12 0xffffff8003544000 0x92000    0x92000    com.apple.kec.corecrypto (11.1) F5F1255F-6552-3CF4-A9DB-D60EFDEB4A9A <8 7 6 5 3 1>
```
अंक 9 तक सूचीबद्ध ड्राइवर **पता 0 में लोड** होते हैं। इसका मतलब है कि वे वास्तविक ड्राइवर नहीं हैं बल्कि **कर्नेल का हिस्सा हैं और उन्हें अनलोड नहीं किया जा सकता**।

विशिष्ट एक्सटेंशन्स खोजने के लिए आप इस्तेमाल कर सकते हैं:
```bash
kextfind -bundle-id com.apple.iokit.IOReportFamily #Search by full bundle-id
kextfind -bundle-id -substring IOR #Search by substring in bundle-id
```
कर्नेल एक्सटेंशन को लोड और अनलोड करने के लिए करें:
```bash
kextload com.apple.iokit.IOReportFamily
kextunload com.apple.iokit.IOReportFamily
```
## IORegistry

**IORegistry** मैकओएस और आईओएस के IOKit framework का एक महत्वपूर्ण हिस्सा है जो सिस्टम की हार्डवेयर कॉन्फ़िगरेशन और स्थिति को प्रतिनिधित्व करने के लिए एक डेटाबेस का कार्य करता है। यह एक **वर्गीकृत संग्रह है जो सिस्टम पर लोड की गई सभी हार्डवेयर और ड्राइवर्स** को प्रतिनिधित्व करता है, और उनके आपसी संबंधों को।

आप **`ioreg`** का उपयोग करके IORegistry को कंसोल से जांच सकते हैं (विशेष रूप से आईओएस के लिए उपयुक्त)।
```bash
ioreg -l #List all
ioreg -w 0 #Not cut lines
ioreg -p <plane> #Check other plane
```
आप **`IORegistryExplorer`** को [**https://developer.apple.com/download/all/**](https://developer.apple.com/download/all/) से **Xcode Additional Tools** से डाउनलोड कर सकते हैं और **ग्राफिकल** इंटरफेस के माध्यम से **macOS IORegistry** की जांच कर सकते हैं।

<figure><img src="../../../.gitbook/assets/image (695).png" alt="" width="563"><figcaption></figcaption></figure>

IORegistryExplorer में, "planes" का उपयोग विभिन्न ऑब्जेक्ट्स के बीच संबंधों को संगठित और प्रदर्शित करने के लिए किया जाता है। प्रत्येक plane एक विशिष्ट प्रकार के संबंध को प्रतिनिधित्व करता है या सिस्टम के हार्डवेयर और ड्राइवर कॉन्फ़िगरेशन का विशेष दृश्य प्रदर्शित करता है। यहां कुछ सामान्य planes हैं जो आप IORegistryExplorer में देख सकते हैं:

1. **IOService Plane**: यह सबसे सामान्य plane है, जो ड्राइवर्स और nubs (ड्राइवर्स के बीच संचार चैनल) को प्रतिनिधित करने वाले सेवा ऑब्ज
```objectivec
#import <Foundation/Foundation.h>
#import <IOKit/IOKitLib.h>

int main(int argc, const char * argv[]) {
@autoreleasepool {
// Get a reference to the service using its name
CFMutableDictionaryRef matchingDict = IOServiceMatching("YourServiceNameHere");
if (matchingDict == NULL) {
NSLog(@"Failed to create matching dictionary");
return -1;
}

// Obtain an iterator over all matching services
io_iterator_t iter;
kern_return_t kr = IOServiceGetMatchingServices(kIOMasterPortDefault, matchingDict, &iter);
if (kr != KERN_SUCCESS) {
NSLog(@"Failed to get matching services");
return -1;
}

// Get a reference to the first service (assuming it exists)
io_service_t service = IOIteratorNext(iter);
if (!service) {
NSLog(@"No matching service found");
IOObjectRelease(iter);
return -1;
}

// Open a connection to the service
io_connect_t connect;
kr = IOServiceOpen(service, mach_task_self(), 0, &connect);
if (kr != KERN_SUCCESS) {
NSLog(@"Failed to open service");
IOObjectRelease(service);
IOObjectRelease(iter);
return -1;
}

// Call a method on the service
// Assume the method has a selector of 0, and takes no arguments
kr = IOConnectCallScalarMethod(connect, 0, NULL, 0, NULL, NULL);
if (kr != KERN_SUCCESS) {
NSLog(@"Failed to call method");
}

// Cleanup
IOServiceClose(connect);
IOObjectRelease(service);
IOObjectRelease(iter);
}
return 0;
}
```
इसके अलावा **`IOConnectCallScalarMethod`** जैसे IOKit फ़ंक्शन को कॉल करने के लिए **`IOConnectCallMethod`**, **`IOConnectCallStructMethod`** जैसे **अन्य** फ़ंक्शन हो सकते हैं।

## ड्राइवर एंट्री पॉइंट का रिवर्सिंग

आप इन्हें उदाहरण के लिए [**फर्मवेयर इमेज (ipsw)**](./#ipsw) से प्राप्त कर सकते हैं। फिर, इसे अपने पसंदीदा डीकंपाइलर में लोड करें।

आप **`externalMethod`** फ़ंक्शन का डीकंपाइलिंग शुरू कर सकते हैं क्योंकि यह ड्राइवर फ़ंक्शन है जो कॉल प्राप्त करेगा और सही फ़ंक्शन को कॉल करेगा:

<figure><img src="../../../.gitbook/assets/image (696).png" alt="" width="315"><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (697).png" alt=""><figcaption></figcaption></figure>

वह भयानक कॉल डीमैगल्ड का मतलब है:
```cpp
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
{% endcode %}

पिछले परिभाषण में ध्यान दें कि **`self`** पैरामीटर छूट गया है, अच्छी परिभाषा यह होगी:

{% code overflow="wrap" %}
```cpp
IOUserClient2022::dispatchExternalMethod(self, unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
{% endcode %}

वास्तव में, आप असली परिभाषा [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388) में पा सकते हैं:
```cpp
IOUserClient2022::dispatchExternalMethod(uint32_t selector, IOExternalMethodArgumentsOpaque *arguments,
const IOExternalMethodDispatch2022 dispatchArray[], size_t dispatchArrayCount,
OSObject * target, void * reference)
```
इस जानकारी के साथ आप Ctrl+Right -> `संपादन फ़ंक्शन हस्ताक्षर` को पुनः लिख सकते हैं और जाने गए प्रकार सेट कर सकते हैं:

<figure><img src="../../../.gitbook/assets/image (702).png" alt=""><figcaption></figcaption></figure>

नया डीकंपाइल कोड इस तरह दिखेगा:

<figure><img src="../../../.gitbook/assets/image (703).png" alt=""><figcaption></figcaption></figure>

अगले कदम के लिए हमें **`IOExternalMethodDispatch2022`** स्ट्रक्टर को परिभाषित करना होगा। यह [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176) में ओपनसोर्स है, आप इसे परिभाषित कर सकते हैं:

<figure><img src="../../../.gitbook/assets/image (698).png" alt=""><figcaption></figcaption></figure>

अब, `(IOExternalMethodDispatch2022 *)&sIOExternalMethodArray` का पालन करते हुए आप बहुत सारे डेटा देख सकते हैं:

<figure><img src="../../../.gitbook/assets/image (704).png" alt="" width="563"><figcaption></figcaption></figure>

डेटा प्रकार को **`IOExternalMethodDispatch2022:`** में बदलें:

<figure><img src="../../../.gitbook/assets/image (705).png" alt="" width="375"><figcaption></figcaption></figure>

बदलाव के बाद:

<figure><img src="../../../.gitbook/assets/image (707).png" alt="" width="563"><figcaption></figcaption></figure>

और जैसा कि हम अब वहाँ हैं, हमारे पास **7 तत्वों का एक सरणी** है (अंतिम डीकंपाइल कोड की जांच करें), 7 तत्वों की एक सरणी बनाने के लिए क्लिक करें:

<figure><img src="../../../.gitbook/assets/image (708).png" alt="" width="563"><figcaption></figcaption></figure>

सरणी बनाई जाने के बाद आप सभी निर्यात किए गए फ़ंक्शन देख सकते हैं:

<figure><img src="../../../.gitbook/assets/image (709).png" alt=""><figcaption></figcaption></figure>

{% hint style="success" %}
अगर आप याद करते हैं, तो **उपयोगकर्ता स्थान से निर्यात किए गए** फ़ंक्शन को **कॉल** करने के लिए हमें फ़ंक्शन का नाम नहीं बुलाने की आवश्यकता नहीं है, बल्कि **सेलेक्टर नंबर** को। यहाँ आप देख सकते हैं कि सेलेक्टर **0** फ़ंक्शन **`initializeDecoder`** है, सेलेक्टर **1** **`startDecoder`** है, सेलेक्टर **2** **`initializeEncoder`** है...
{% endhint %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) **grupo de Discord** o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live).
* **Comparte tus trucos de hacking enviando PR a** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **y** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
