# macOS XPC

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

XPC, जिसका मतलब XNU (macOS द्वारा उपयोग किया जाने वाला कर्नेल) इंटर-प्रोसेस संचार है, macOS और iOS पर **प्रक्रियाओं के बीच संचार** के लिए एक ढांचा है। XPC विभिन्न प्रक्रियाओं के बीच **सुरक्षित, असिंक्रोनस विधि कॉल करने** के लिए एक तंत्र प्रदान करता है। यह एप्पल के सुरक्षा सिद्धांत का एक हिस्सा है, जो **विशेषाधिकार-सेपरेटेड एप्लिकेशन** के निर्माण की अनुमति देता है जहाँ प्रत्येक **घटक** केवल **उन्हीं अनुमतियों** के साथ चलता है जिनकी उसे अपने कार्य को करने के लिए आवश्यकता होती है, इस प्रकार एक समझौता किए गए प्रक्रिया से संभावित नुकसान को सीमित करता है।

XPC एक प्रकार के इंटर-प्रोसेस संचार (IPC) का उपयोग करता है, जो एक सेट है विभिन्न कार्यक्रमों के लिए जो एक ही प्रणाली पर चल रहे हैं, डेटा को आगे-पीछे भेजने के लिए।

XPC के प्राथमिक लाभों में शामिल हैं:

1. **सुरक्षा**: विभिन्न प्रक्रियाओं में कार्य को अलग करके, प्रत्येक प्रक्रिया को केवल वही अनुमतियाँ दी जा सकती हैं जिनकी उसे आवश्यकता होती है। इसका मतलब है कि यदि एक प्रक्रिया समझौता कर ली जाती है, तो उसके पास नुकसान करने की सीमित क्षमता होती है।
2. **स्थिरता**: XPC क्रैश को उस घटक तक सीमित करने में मदद करता है जहाँ वे होते हैं। यदि एक प्रक्रिया क्रैश होती है, तो इसे बिना बाकी प्रणाली को प्रभावित किए पुनः प्रारंभ किया जा सकता है।
3. **प्रदर्शन**: XPC आसान समवर्तीता की अनुमति देता है, क्योंकि विभिन्न कार्यों को विभिन्न प्रक्रियाओं में एक साथ चलाया जा सकता है।

एकमात्र **नुकसान** यह है कि **एक एप्लिकेशन को कई प्रक्रियाओं में अलग करना** और उन्हें XPC के माध्यम से संचारित करना **कम प्रभावी** है। लेकिन आज की प्रणालियों में यह लगभग ध्यान देने योग्य नहीं है और लाभ बेहतर हैं।

## Application Specific XPC services

एक एप्लिकेशन के XPC घटक **एप्लिकेशन के अंदर ही होते हैं।** उदाहरण के लिए, Safari में आप इन्हें **`/Applications/Safari.app/Contents/XPCServices`** में पा सकते हैं। इनके पास **`.xpc`** एक्सटेंशन होता है (जैसे **`com.apple.Safari.SandboxBroker.xpc`**) और ये मुख्य बाइनरी के साथ **बंडल** होते हैं: `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/MacOS/com.apple.Safari.SandboxBroker` और एक `Info.plist: /Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/Info.plist`

जैसा कि आप सोच रहे होंगे, एक **XPC घटक के पास अन्य XPC घटकों या मुख्य ऐप बाइनरी की तुलना में विभिन्न अधिकार और विशेषताएँ होंगी।** सिवाय इसके कि यदि एक XPC सेवा को [**JoinExistingSession**](https://developer.apple.com/documentation/bundleresources/information_property_list/xpcservice/joinexistingsession) इसके **Info.plist** फ़ाइल में “True” पर सेट किया गया है। इस मामले में, XPC सेवा उस **सुरक्षा सत्र में चलेगी** जो एप्लिकेशन ने इसे कॉल किया।

XPC सेवाएँ **launchd** द्वारा आवश्यकतानुसार **शुरू** की जाती हैं और सभी कार्यों के **पूर्ण** होने पर सिस्टम संसाधनों को मुक्त करने के लिए **बंद** कर दी जाती हैं। **एप्लिकेशन-विशिष्ट XPC घटक केवल एप्लिकेशन द्वारा उपयोग किए जा सकते हैं**, इस प्रकार संभावित कमजोरियों से संबंधित जोखिम को कम करते हैं।

## System Wide XPC services

सिस्टम-व्यापी XPC सेवाएँ सभी उपयोगकर्ताओं के लिए सुलभ हैं। ये सेवाएँ, चाहे launchd या Mach-प्रकार की हों, उन्हें **plist** फ़ाइलों में परिभाषित करने की आवश्यकता होती है जो निर्दिष्ट निर्देशिकाओं में स्थित होती हैं जैसे **`/System/Library/LaunchDaemons`**, **`/Library/LaunchDaemons`**, **`/System/Library/LaunchAgents`**, या **`/Library/LaunchAgents`**।

इन plist फ़ाइलों में एक कुंजी होगी जिसे **`MachServices`** कहा जाता है जिसमें सेवा का नाम होगा, और एक कुंजी होगी जिसे **`Program`** कहा जाता है जिसमें बाइनरी का पथ होगा:
```xml
cat /Library/LaunchDaemons/com.jamf.management.daemon.plist

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>Program</key>
<string>/Library/Application Support/JAMF/Jamf.app/Contents/MacOS/JamfDaemon.app/Contents/MacOS/JamfDaemon</string>
<key>AbandonProcessGroup</key>
<true/>
<key>KeepAlive</key>
<true/>
<key>Label</key>
<string>com.jamf.management.daemon</string>
<key>MachServices</key>
<dict>
<key>com.jamf.management.daemon.aad</key>
<true/>
<key>com.jamf.management.daemon.agent</key>
<true/>
<key>com.jamf.management.daemon.binary</key>
<true/>
<key>com.jamf.management.daemon.selfservice</key>
<true/>
<key>com.jamf.management.daemon.service</key>
<true/>
</dict>
<key>RunAtLoad</key>
<true/>
</dict>
</plist>
```
The ones in **`LaunchDameons`** root द्वारा चलाए जाते हैं। इसलिए यदि एक अप्रिविलेज्ड प्रक्रिया इनमें से किसी के साथ बात कर सकती है, तो यह विशेषाधिकार बढ़ाने में सक्षम हो सकती है।

## XPC ऑब्जेक्ट्स

* **`xpc_object_t`**

हर XPC संदेश एक डिक्शनरी ऑब्जेक्ट है जो सीरियलाइजेशन और डीसिरियलाइजेशन को सरल बनाता है। इसके अलावा, `libxpc.dylib` अधिकांश डेटा प्रकारों की घोषणा करता है, इसलिए यह संभव है कि प्राप्त डेटा अपेक्षित प्रकार का हो। C API में हर ऑब्जेक्ट एक `xpc_object_t` है (और इसका प्रकार `xpc_get_type(object)` का उपयोग करके जांचा जा सकता है)।\
इसके अलावा, फ़ंक्शन `xpc_copy_description(object)` का उपयोग ऑब्जेक्ट का स्ट्रिंग प्रतिनिधित्व प्राप्त करने के लिए किया जा सकता है, जो डिबगिंग उद्देश्यों के लिए उपयोगी हो सकता है।\
इन ऑब्जेक्ट्स में कुछ विधियाँ भी होती हैं जिन्हें कॉल किया जा सकता है जैसे `xpc_<object>_copy`, `xpc_<object>_equal`, `xpc_<object>_hash`, `xpc_<object>_serialize`, `xpc_<object>_deserialize`...

`xpc_object_t` को `xpc_<objetType>_create` फ़ंक्शन को कॉल करके बनाया जाता है, जो आंतरिक रूप से `_xpc_base_create(Class, Size)` को कॉल करता है जहाँ ऑब्जेक्ट की क्लास का प्रकार (एक `XPC_TYPE_*` में से) और इसका आकार (कुछ अतिरिक्त 40B मेटाडेटा के लिए आकार में जोड़ा जाएगा) निर्दिष्ट किया जाता है। जिसका अर्थ है कि ऑब्जेक्ट का डेटा 40B के ऑफसेट से शुरू होगा।\
इसलिए, `xpc_<objectType>_t` एक प्रकार का `xpc_object_t` का उपवर्ग है जो `os_object_t*` का उपवर्ग होगा।

{% hint style="warning" %}
ध्यान दें कि यह डेवलपर होना चाहिए जो `xpc_dictionary_[get/set]_<objectType>` का उपयोग करके एक कुंजी के प्रकार और वास्तविक मान को प्राप्त या सेट करता है।
{% endhint %}

* **`xpc_pipe`**

एक **`xpc_pipe`** एक FIFO पाइप है जिसका उपयोग प्रक्रियाएँ संवाद करने के लिए कर सकती हैं (संवाद में Mach संदेशों का उपयोग होता है)।\
एक XPC सर्वर बनाने के लिए `xpc_pipe_create()` या `xpc_pipe_create_from_port()` को कॉल करके इसे एक विशिष्ट Mach पोर्ट का उपयोग करके बनाया जा सकता है। फिर, संदेश प्राप्त करने के लिए `xpc_pipe_receive` और `xpc_pipe_try_receive` को कॉल किया जा सकता है।

ध्यान दें कि **`xpc_pipe`** ऑब्जेक्ट एक **`xpc_object_t`** है जिसमें इसके स्ट्रक्चर में उपयोग किए गए दो Mach पोर्ट और नाम (यदि कोई हो) के बारे में जानकारी होती है। नाम, उदाहरण के लिए, डेमन `secinitd` अपने plist `/System/Library/LaunchDaemons/com.apple.secinitd.plist` में पाइप को `com.apple.secinitd` के रूप में कॉन्फ़िगर करता है।

एक **`xpc_pipe`** का उदाहरण **bootstrap pipe** है जो **`launchd`** द्वारा बनाया गया है जिससे Mach पोर्ट साझा करना संभव हो जाता है।

* **`NSXPC*`**

ये Objective-C उच्च स्तर के ऑब्जेक्ट हैं जो XPC कनेक्शनों का अमूर्तकरण करने की अनुमति देते हैं।\
इसके अलावा, इन ऑब्जेक्ट्स को DTrace के साथ डिबग करना पिछले ऑब्जेक्ट्स की तुलना में आसान है।

* **`GCD Queues`**

XPC संदेशों को पास करने के लिए GCD का उपयोग करता है, इसके अलावा यह कुछ डिस्पैच कतारें उत्पन्न करता है जैसे `xpc.transactionq`, `xpc.io`, `xpc-events.add-listenerq`, `xpc.service-instance`...

## XPC सेवाएँ

ये **`.xpc`** एक्सटेंशन वाले बंडल हैं जो अन्य परियोजनाओं के **`XPCServices`** फ़ोल्डर के अंदर स्थित हैं और `Info.plist` में उनके पास `CFBundlePackageType` **`XPC!`** पर सेट होता है।\
इस फ़ाइल में अन्य कॉन्फ़िगरेशन कुंजी होती हैं जैसे `ServiceType` जो Application, User, System या `_SandboxProfile` हो सकती है जो एक सैंडबॉक्स को परिभाषित कर सकती है या `_AllowedClients` जो आवश्यक अधिकार या ID को इंगित कर सकती है जो सेवा से संपर्क करने के लिए आवश्यक है। ये और अन्य कॉन्फ़िगरेशन विकल्प सेवा को लॉन्च करते समय कॉन्फ़िगर करने के लिए उपयोगी होंगे।

### सेवा शुरू करना

ऐप **`xpc_connection_create_mach_service`** का उपयोग करके XPC सेवा से **कनेक्ट** करने का प्रयास करता है, फिर launchd डेमन को ढूंढता है और **`xpcproxy`** शुरू करता है। **`xpcproxy`** कॉन्फ़िगर की गई प्रतिबंधों को लागू करता है और प्रदान किए गए FDs और Mach पोर्ट के साथ सेवा को स्पॉन करता है।

XPC सेवा की खोज की गति में सुधार करने के लिए, एक कैश का उपयोग किया जाता है।

`xpcproxy` की क्रियाओं को ट्रेस करना संभव है:
```bash
supraudit S -C -o /tmp/output /dev/auditpipe
```
The XPC लाइब्रेरी `kdebug` का उपयोग करती है ताकि क्रियाओं को लॉग किया जा सके जो `xpc_ktrace_pid0` और `xpc_ktrace_pid1` को कॉल करती हैं। जो कोड इसका उपयोग करते हैं वे प्रलेखित नहीं हैं इसलिए इन्हें `/usr/share/misc/trace.codes` में जोड़ना आवश्यक है। इनके पास `0x29` उपसर्ग है और उदाहरण के लिए एक है `0x29000004`: `XPC_serializer_pack`।\
उपकरण `xpcproxy` उपसर्ग `0x22` का उपयोग करता है, उदाहरण के लिए: `0x2200001c: xpcproxy:will_do_preexec`।

## XPC इवेंट संदेश

ऐप्लिकेशन विभिन्न इवेंट **संदेशों** के लिए **सदस्यता** ले सकते हैं, जिससे उन्हें ऐसे इवेंट होने पर **आवश्यकतानुसार आरंभ** किया जा सके। इन सेवाओं के लिए **सेटअप** `launchd plist फाइलों` में किया जाता है, जो **पिछली फाइलों के समान निर्देशिकाओं** में स्थित होती हैं और एक अतिरिक्त **`LaunchEvent`** कुंजी होती है।

### XPC कनेक्टिंग प्रक्रिया जांच

जब एक प्रक्रिया XPC कनेक्शन के माध्यम से एक विधि को कॉल करने की कोशिश करती है, तो **XPC सेवा को यह जांचना चाहिए कि क्या उस प्रक्रिया को कनेक्ट करने की अनुमति है**। यहाँ इसे जांचने के सामान्य तरीके और सामान्य pitfalls हैं:

{% content-ref url="macos-xpc-connecting-process-check/" %}
[macos-xpc-connecting-process-check](macos-xpc-connecting-process-check/)
{% endcontent-ref %}

## XPC प्राधिकरण

Apple ऐप्स को **कुछ अधिकारों को कॉन्फ़िगर करने और उन्हें प्राप्त करने का तरीका** निर्धारित करने की अनुमति भी देता है, इसलिए यदि कॉल करने वाली प्रक्रिया के पास ये हैं तो इसे XPC सेवा से एक विधि को **कॉल करने की अनुमति होगी**:

{% content-ref url="macos-xpc-authorization.md" %}
[macos-xpc-authorization.md](macos-xpc-authorization.md)
{% endcontent-ref %}

## XPC स्निफर

XPC संदेशों को स्निफ़ करने के लिए आप [**xpcspy**](https://github.com/hot3eed/xpcspy) का उपयोग कर सकते हैं जो **Frida** का उपयोग करता है।
```bash
# Install
pip3 install xpcspy
pip3 install xpcspy --no-deps # To not make xpcspy install Frida 15 and downgrade your Frida installation

# Start sniffing
xpcspy -U -r -W <bundle-id>
## Using filters (i: for input, o: for output)
xpcspy -U <prog-name> -t 'i:com.apple.*' -t 'o:com.apple.*' -r
```
एक और संभावित उपकरण जिसका उपयोग किया जा सकता है वह है [**XPoCe2**](https://newosxbook.com/tools/XPoCe2.html).

## XPC संचार C कोड उदाहरण

{% tabs %}
{% tab title="xpc_server.c" %}
```c
// gcc xpc_server.c -o xpc_server

#include <xpc/xpc.h>

static void handle_event(xpc_object_t event) {
if (xpc_get_type(event) == XPC_TYPE_DICTIONARY) {
// Print received message
const char* received_message = xpc_dictionary_get_string(event, "message");
printf("Received message: %s\n", received_message);

// Create a response dictionary
xpc_object_t response = xpc_dictionary_create(NULL, NULL, 0);
xpc_dictionary_set_string(response, "received", "received");

// Send response
xpc_connection_t remote = xpc_dictionary_get_remote_connection(event);
xpc_connection_send_message(remote, response);

// Clean up
xpc_release(response);
}
}

static void handle_connection(xpc_connection_t connection) {
xpc_connection_set_event_handler(connection, ^(xpc_object_t event) {
handle_event(event);
});
xpc_connection_resume(connection);
}

int main(int argc, const char *argv[]) {
xpc_connection_t service = xpc_connection_create_mach_service("xyz.hacktricks.service",
dispatch_get_main_queue(),
XPC_CONNECTION_MACH_SERVICE_LISTENER);
if (!service) {
fprintf(stderr, "Failed to create service.\n");
exit(EXIT_FAILURE);
}

xpc_connection_set_event_handler(service, ^(xpc_object_t event) {
xpc_type_t type = xpc_get_type(event);
if (type == XPC_TYPE_CONNECTION) {
handle_connection(event);
}
});

xpc_connection_resume(service);
dispatch_main();

return 0;
}
```
{% endtab %}

{% tab title="xpc_client.c" %}
```c
// gcc xpc_client.c -o xpc_client

#include <xpc/xpc.h>

int main(int argc, const char *argv[]) {
xpc_connection_t connection = xpc_connection_create_mach_service("xyz.hacktricks.service", NULL, XPC_CONNECTION_MACH_SERVICE_PRIVILEGED);

xpc_connection_set_event_handler(connection, ^(xpc_object_t event) {
if (xpc_get_type(event) == XPC_TYPE_DICTIONARY) {
// Print received message
const char* received_message = xpc_dictionary_get_string(event, "received");
printf("Received message: %s\n", received_message);
}
});

xpc_connection_resume(connection);

xpc_object_t message = xpc_dictionary_create(NULL, NULL, 0);
xpc_dictionary_set_string(message, "message", "Hello, Server!");

xpc_connection_send_message(connection, message);

dispatch_main();

return 0;
}
```
{% endtab %}

{% tab title="xyz.hacktricks.service.plist" %}
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"> <plist version="1.0">
<dict>
<key>Label</key>
<string>xyz.hacktricks.service</string>
<key>MachServices</key>
<dict>
<key>xyz.hacktricks.service</key>
<true/>
</dict>
<key>Program</key>
<string>/tmp/xpc_server</string>
<key>ProgramArguments</key>
<array>
<string>/tmp/xpc_server</string>
</array>
</dict>
</plist>
```
{% endtab %}
{% endtabs %}
```bash
# Compile the server & client
gcc xpc_server.c -o xpc_server
gcc xpc_client.c -o xpc_client

# Save server on it's location
cp xpc_server /tmp

# Load daemon
sudo cp xyz.hacktricks.service.plist /Library/LaunchDaemons
sudo launchctl load /Library/LaunchDaemons/xyz.hacktricks.service.plist

# Call client
./xpc_client

# Clean
sudo launchctl unload /Library/LaunchDaemons/xyz.hacktricks.service.plist
sudo rm /Library/LaunchDaemons/xyz.hacktricks.service.plist /tmp/xpc_server
```
## XPC संचार उद्देश्य-सी कोड उदाहरण

{% tabs %}
{% tab title="oc_xpc_server.m" %}
```objectivec
// gcc -framework Foundation oc_xpc_server.m -o oc_xpc_server
#include <Foundation/Foundation.h>

@protocol MyXPCProtocol
- (void)sayHello:(NSString *)some_string withReply:(void (^)(NSString *))reply;
@end

@interface MyXPCObject : NSObject <MyXPCProtocol>
@end


@implementation MyXPCObject
- (void)sayHello:(NSString *)some_string withReply:(void (^)(NSString *))reply {
NSLog(@"Received message: %@", some_string);
NSString *response = @"Received";
reply(response);
}
@end

@interface MyDelegate : NSObject <NSXPCListenerDelegate>
@end


@implementation MyDelegate

- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)newConnection {
newConnection.exportedInterface = [NSXPCInterface interfaceWithProtocol:@protocol(MyXPCProtocol)];

MyXPCObject *my_object = [MyXPCObject new];

newConnection.exportedObject = my_object;

[newConnection resume];
return YES;
}
@end

int main(void) {

NSXPCListener *listener = [[NSXPCListener alloc] initWithMachServiceName:@"xyz.hacktricks.svcoc"];

id <NSXPCListenerDelegate> delegate = [MyDelegate new];
listener.delegate = delegate;
[listener resume];

sleep(10); // Fake something is done and then it ends
}
```
{% endtab %}

{% tab title="oc_xpc_client.m" %}
```objectivec
// gcc -framework Foundation oc_xpc_client.m -o oc_xpc_client
#include <Foundation/Foundation.h>

@protocol MyXPCProtocol
- (void)sayHello:(NSString *)some_string withReply:(void (^)(NSString *))reply;
@end

int main(void) {
NSXPCConnection *connection = [[NSXPCConnection alloc] initWithMachServiceName:@"xyz.hacktricks.svcoc" options:NSXPCConnectionPrivileged];
connection.remoteObjectInterface = [NSXPCInterface interfaceWithProtocol:@protocol(MyXPCProtocol)];
[connection resume];

[[connection remoteObjectProxy] sayHello:@"Hello, Server!" withReply:^(NSString *response) {
NSLog(@"Received response: %@", response);
}];

[[NSRunLoop currentRunLoop] run];

return 0;
}
```
{% endtab %}

{% tab title="xyz.hacktricks.svcoc.plist" %}
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"> <plist version="1.0">
<dict>
<key>Label</key>
<string>xyz.hacktricks.svcoc</string>
<key>MachServices</key>
<dict>
<key>xyz.hacktricks.svcoc</key>
<true/>
</dict>
<key>Program</key>
<string>/tmp/oc_xpc_server</string>
<key>ProgramArguments</key>
<array>
<string>/tmp/oc_xpc_server</string>
</array>
</dict>
</plist>
```
{% endtab %}
{% endtabs %}
```bash
# Compile the server & client
gcc -framework Foundation oc_xpc_server.m -o oc_xpc_server
gcc -framework Foundation oc_xpc_client.m -o oc_xpc_client

# Save server on it's location
cp oc_xpc_server /tmp

# Load daemon
sudo cp xyz.hacktricks.svcoc.plist /Library/LaunchDaemons
sudo launchctl load /Library/LaunchDaemons/xyz.hacktricks.svcoc.plist

# Call client
./oc_xpc_client

# Clean
sudo launchctl unload /Library/LaunchDaemons/xyz.hacktricks.svcoc.plist
sudo rm /Library/LaunchDaemons/xyz.hacktricks.svcoc.plist /tmp/oc_xpc_server
```
## क्लाइंट एक Dylb कोड के अंदर
```objectivec
// gcc -dynamiclib -framework Foundation oc_xpc_client.m -o oc_xpc_client.dylib
// gcc injection example:
// DYLD_INSERT_LIBRARIES=oc_xpc_client.dylib /path/to/vuln/bin

#import <Foundation/Foundation.h>

@protocol MyXPCProtocol
- (void)sayHello:(NSString *)some_string withReply:(void (^)(NSString *))reply;
@end

__attribute__((constructor))
static void customConstructor(int argc, const char **argv)
{
NSString*  _serviceName = @"xyz.hacktricks.svcoc";

NSXPCConnection* _agentConnection = [[NSXPCConnection alloc] initWithMachServiceName:_serviceName options:4096];

[_agentConnection setRemoteObjectInterface:[NSXPCInterface interfaceWithProtocol:@protocol(MyXPCProtocol)]];

[_agentConnection resume];

[[_agentConnection remoteObjectProxyWithErrorHandler:^(NSError* error) {
(void)error;
NSLog(@"Connection Failure");
}] sayHello:@"Hello, Server!" withReply:^(NSString *response) {
NSLog(@"Received response: %@", response);
}    ];
NSLog(@"Done!");

return;
}
```
## Remote XPC

यह कार्यक्षमता `RemoteXPC.framework` (जो `libxpc` से है) विभिन्न होस्टों के माध्यम से XPC के माध्यम से संवाद करने की अनुमति देती है।\
जो सेवाएँ दूरस्थ XPC का समर्थन करती हैं, उनके plist में कुंजी UsesRemoteXPC होगी जैसे कि `/System/Library/LaunchDaemons/com.apple.SubmitDiagInfo.plist` के मामले में है। हालाँकि, सेवा `launchd` के साथ पंजीकृत होगी, यह `UserEventAgent` है जिसमें प्लगइन्स `com.apple.remoted.plugin` और `com.apple.remoteservicediscovery.events.plugin` कार्यक्षमता प्रदान करते हैं।

इसके अलावा, `RemoteServiceDiscovery.framework` `com.apple.remoted.plugin` से जानकारी प्राप्त करने की अनुमति देता है, जो कार्यों को उजागर करता है जैसे `get_device`, `get_unique_device`, `connect`...

एक बार जब कनेक्ट का उपयोग किया जाता है और सेवा का सॉकेट `fd` एकत्र किया जाता है, तो `remote_xpc_connection_*` वर्ग का उपयोग करना संभव है।

यह CLI टूल `/usr/libexec/remotectl` का उपयोग करके दूरस्थ सेवाओं के बारे में जानकारी प्राप्त करना संभव है, जिसमें निम्नलिखित पैरामीटर शामिल हैं:
```bash
/usr/libexec/remotectl list # Get bridge devices
/usr/libexec/remotectl show ...# Get device properties and services
/usr/libexec/remotectl dumpstate # Like dump withuot indicateing a servie
/usr/libexec/remotectl [netcat|relay] ... # Expose a service in a port
...
```
BridgeOS और होस्ट के बीच संचार एक समर्पित IPv6 इंटरफेस के माध्यम से होता है। `MultiverseSupport.framework` सॉकेट स्थापित करने की अनुमति देता है जिनका `fd` संचार के लिए उपयोग किया जाएगा।\
इन संचारों को `netstat`, `nettop` या ओपन-सोर्स विकल्प `netbottom` का उपयोग करके पाया जा सकता है।

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
