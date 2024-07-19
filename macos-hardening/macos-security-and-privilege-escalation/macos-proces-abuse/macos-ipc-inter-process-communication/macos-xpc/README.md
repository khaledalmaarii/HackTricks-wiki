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

## Temel Bilgiler

XPC, macOS tarafından kullanılan XNU (çekirdek) arasındaki İletişim için bir çerçevedir ve macOS ve iOS'ta **işlemler arası iletişim** sağlar. XPC, sistemdeki farklı işlemler arasında **güvenli, asenkron yöntem çağrıları yapma** mekanizması sunar. Bu, her bir **bileşenin** işini yapmak için **gereken izinlerle** çalıştığı **ayrılmış ayrıcalıklarla uygulamalar** oluşturulmasına olanak tanıyarak, tehlikeye atılmış bir işlemin potansiyel zararını sınırlamaktadır.

XPC, aynı sistemde çalışan farklı programların veri göndermesi ve alması için bir dizi yöntem olan İşlemler Arası İletişim (IPC) biçimini kullanır.

XPC'nin başlıca faydaları şunlardır:

1. **Güvenlik**: Çalışmayı farklı işlemlere ayırarak, her bir işleme yalnızca ihtiyaç duyduğu izinler verilebilir. Bu, bir işlem tehlikeye atılsa bile, zarar verme yeteneğinin sınırlı olduğu anlamına gelir.
2. **Kararlılık**: XPC, çökme durumlarını meydana geldiği bileşene izole etmeye yardımcı olur. Bir işlem çökerse, sistemin geri kalanını etkilemeden yeniden başlatılabilir.
3. **Performans**: XPC, farklı görevlerin farklı işlemlerde aynı anda çalıştırılmasına olanak tanıyarak kolay bir eşzamanlılık sağlar.

Tek **dezavantaj**, **bir uygulamayı birkaç işleme ayırmanın** ve bunların XPC aracılığıyla iletişim kurmasının **daha az verimli** olmasıdır. Ancak günümüz sistemlerinde bu neredeyse fark edilmez ve faydalar daha iyidir.

## Uygulama Özel XPC hizmetleri

Bir uygulamanın XPC bileşenleri **uygulamanın kendisinin içindedir.** Örneğin, Safari'de bunları **`/Applications/Safari.app/Contents/XPCServices`** dizininde bulabilirsiniz. **`.xpc`** uzantısına sahiptirler (örneğin **`com.apple.Safari.SandboxBroker.xpc`**) ve ana ikili dosya ile birlikte paketlenmiştir: `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/MacOS/com.apple.Safari.SandboxBroker` ve bir `Info.plist: /Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/Info.plist`

Bir **XPC bileşeninin diğer XPC bileşenlerinden veya ana uygulama ikili dosyasından farklı haklara ve ayrıcalıklara sahip olacağını** düşünebilirsiniz. **EXCEPT** bir XPC hizmeti, **Info.plist** dosyasında **JoinExistingSession** [**True**](https://developer.apple.com/documentation/bundleresources/information_property_list/xpcservice/joinexistingsession) olarak ayarlandığında. Bu durumda, XPC hizmeti, onu çağıran uygulama ile **aynı güvenlik oturumunda** çalışacaktır.

XPC hizmetleri, gerektiğinde **launchd** tarafından **başlatılır** ve tüm görevler **tamamlandığında** sistem kaynaklarını serbest bırakmak için **kapalı** tutulur. **Uygulama özel XPC bileşenleri yalnızca uygulama tarafından kullanılabilir**, böylece potansiyel güvenlik açıklarıyla ilişkili riski azaltır.

## Sistem Genelinde XPC hizmetleri

Sistem genelindeki XPC hizmetleri tüm kullanıcılar tarafından erişilebilir. Bu hizmetler, ya launchd ya da Mach türünde olup, **`/System/Library/LaunchDaemons`**, **`/Library/LaunchDaemons`**, **`/System/Library/LaunchAgents`** veya **`/Library/LaunchAgents`** gibi belirli dizinlerde bulunan plist dosyalarında **tanımlanmalıdır**.

Bu plist dosyalarında, hizmetin adıyla birlikte **`MachServices`** adında bir anahtar ve ikili dosyanın yolunu içeren **`Program`** adında bir anahtar bulunacaktır:
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
The ones in **`LaunchDameons`** root tarafından çalıştırılır. Yani, yetkisiz bir işlem bunlardan biriyle iletişim kurabiliyorsa, yetkileri artırma olanağına sahip olabilir.

## XPC Nesneleri

* **`xpc_object_t`**

Her XPC mesajı, serileştirme ve serileştirmeyi basitleştiren bir sözlük nesnesidir. Ayrıca, `libxpc.dylib` çoğu veri türünü tanımlar, bu nedenle alınan verilerin beklenen türde olması sağlanabilir. C API'sinde her nesne bir `xpc_object_t`'dir (ve türü `xpc_get_type(object)` kullanılarak kontrol edilebilir).\
Ayrıca, `xpc_copy_description(object)` fonksiyonu, hata ayıklama amaçları için yararlı olabilecek nesnenin bir dize temsilini almak için kullanılabilir.\
Bu nesnelerin ayrıca `xpc_<object>_copy`, `xpc_<object>_equal`, `xpc_<object>_hash`, `xpc_<object>_serialize`, `xpc_<object>_deserialize` gibi çağrılacak bazı yöntemleri vardır...

`xpc_object_t` nesneleri, `xpc_<objetType>_create` fonksiyonu çağrılarak oluşturulur; bu, içsel olarak `_xpc_base_create(Class, Size)` fonksiyonunu çağırır ve burada nesnenin sınıf türü (bir `XPC_TYPE_*` türü) ve boyutu belirtilir (metadata için ekstra 40B eklenir). Bu, nesnenin verilerinin 40B'lik bir ofsetten başlayacağı anlamına gelir.\
Bu nedenle, `xpc_<objectType>_t`, `xpc_object_t`'nin bir alt sınıfı gibi bir şeydir ve bu da `os_object_t*`'nin bir alt sınıfı olacaktır.

{% hint style="warning" %}
Anahtarın türünü ve gerçek değerini almak veya ayarlamak için `xpc_dictionary_[get/set]_<objectType>` kullananın geliştirici olması gerektiğini unutmayın.
{% endhint %}

* **`xpc_pipe`**

Bir **`xpc_pipe`**, işlemlerin iletişim kurmak için kullanabileceği bir FIFO borusudur (iletişim Mach mesajlarını kullanır).\
Bir XPC sunucusu oluşturmak için `xpc_pipe_create()` veya belirli bir Mach portu kullanarak oluşturmak için `xpc_pipe_create_from_port()` çağrısı yapılabilir. Ardından, mesajları almak için `xpc_pipe_receive` ve `xpc_pipe_try_receive` çağrılabilir.

**`xpc_pipe`** nesnesinin, kullanılan iki Mach portu ve adı (varsa) hakkında bilgileri içeren bir **`xpc_object_t`** olduğunu unutmayın. Örneğin, plist'inde `/System/Library/LaunchDaemons/com.apple.secinitd.plist` bulunan `secinitd` daemon'u, `com.apple.secinitd` adında bir boru yapılandırır.

Bir **`xpc_pipe`** örneği, Mach portlarını paylaşmayı mümkün kılan **`launchd`** tarafından oluşturulan **bootstrap pipe**'dır.

* **`NSXPC*`**

Bunlar, XPC bağlantılarının soyutlanmasını sağlayan Objective-C yüksek seviyeli nesnelerdir.\
Ayrıca, bu nesneleri DTrace ile hata ayıklamak, önceki nesnelerden daha kolaydır.

* **`GCD Kuyrukları`**

XPC, mesajları iletmek için GCD kullanır, ayrıca `xpc.transactionq`, `xpc.io`, `xpc-events.add-listenerq`, `xpc.service-instance` gibi belirli dağıtım kuyrukları oluşturur...

## XPC Hizmetleri

Bunlar, diğer projelerin **`XPCServices`** klasöründe bulunan **`.xpc`** uzantılı paketlerdir ve `Info.plist` dosyasında `CFBundlePackageType` **`XPC!`** olarak ayarlanmıştır.\
Bu dosya, uygulama, kullanıcı, sistem veya bir sandbox tanımlayabilen `_SandboxProfile` gibi diğer yapılandırma anahtarlarına sahiptir veya hizmete erişmek için gerekli olan haklar veya kimlikleri belirtebilecek `_AllowedClients` anahtarına sahiptir. Bu ve diğer yapılandırma seçenekleri, hizmet başlatıldığında yapılandırmak için yararlı olacaktır.

### Bir Hizmeti Başlatma

Uygulama, `xpc_connection_create_mach_service` kullanarak bir XPC hizmetine **bağlanmaya** çalışır, ardından launchd daemon'u bulur ve **`xpcproxy`**'yi başlatır. **`xpcproxy`**, yapılandırılmış kısıtlamaları uygular ve sağlanan FD'ler ve Mach portları ile hizmeti başlatır.

XPC hizmetinin arama hızını artırmak için bir önbellek kullanılır.

`xpcproxy`'nin eylemlerini izlemek mümkündür:
```bash
supraudit S -C -o /tmp/output /dev/auditpipe
```
XPC kütüphanesi, `xpc_ktrace_pid0` ve `xpc_ktrace_pid1` çağrılarıyla eylemleri günlüğe kaydetmek için `kdebug` kullanır. Kullandığı kodlar belgelenmemiştir, bu nedenle bunları `/usr/share/misc/trace.codes` dosyasına eklemek gereklidir. `0x29` ön ekine sahiptirler ve örneğin biri `0x29000004`: `XPC_serializer_pack`'dır.\
`xpcproxy` aracı `0x22` ön ekini kullanır, örneğin: `0x2200001c: xpcproxy:will_do_preexec`.

## XPC Olay Mesajları

Uygulamalar, böyle olaylar gerçekleştiğinde **talep üzerine başlatılmalarını** sağlayan farklı olay **mesajlarına** **abone** olabilirler. Bu hizmetlerin **kurulumu**, **önceki dosyalarla aynı dizinlerde** bulunan **launchd plist dosyalarında** yapılır ve ekstra bir **`LaunchEvent`** anahtarı içerir.

### XPC Bağlantı Süreci Kontrolü

Bir süreç, bir XPC bağlantısı aracılığıyla bir yöntemi çağırmaya çalıştığında, **XPC hizmeti o sürecin bağlanmasına izin verilip verilmediğini kontrol etmelidir**. Bunu kontrol etmenin yaygın yolları ve yaygın tuzaklar şunlardır:

{% content-ref url="macos-xpc-connecting-process-check/" %}
[macos-xpc-connecting-process-check](macos-xpc-connecting-process-check/)
{% endcontent-ref %}

## XPC Yetkilendirmesi

Apple, uygulamaların **bazı hakları yapılandırmalarına ve bunları nasıl alacaklarına** izin verir, böylece çağıran süreç bu haklara sahipse, XPC hizmetinden bir yöntemi **çağırmasına izin verilir**:

{% content-ref url="macos-xpc-authorization.md" %}
[macos-xpc-authorization.md](macos-xpc-authorization.md)
{% endcontent-ref %}

## XPC Sniffer

XPC mesajlarını dinlemek için [**xpcspy**](https://github.com/hot3eed/xpcspy) kullanabilirsiniz, bu araç **Frida** kullanır.
```bash
# Install
pip3 install xpcspy
pip3 install xpcspy --no-deps # To not make xpcspy install Frida 15 and downgrade your Frida installation

# Start sniffing
xpcspy -U -r -W <bundle-id>
## Using filters (i: for input, o: for output)
xpcspy -U <prog-name> -t 'i:com.apple.*' -t 'o:com.apple.*' -r
```
Başka bir kullanılabilir araç [**XPoCe2**](https://newosxbook.com/tools/XPoCe2.html).

## XPC İletişim C Kodu Örneği

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
## XPC İletişimi Objective-C Kod Örneği

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
## Dylb kodu içindeki İstemci
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

`RemoteXPC.framework` (from `libxpc`) tarafından sağlanan bu işlevsellik, farklı ana bilgisayarlar aracılığıyla XPC ile iletişim kurmayı sağlar.\
Uzaktan XPC'yi destekleyen hizmetler, plist'lerinde `UsesRemoteXPC` anahtarına sahip olacaktır; bu, `/System/Library/LaunchDaemons/com.apple.SubmitDiagInfo.plist` dosyasında olduğu gibi. Ancak, hizmet `launchd` ile kaydedilmiş olsa da, işlevselliği sağlayan `UserEventAgent`'dir; bu, `com.apple.remoted.plugin` ve `com.apple.remoteservicediscovery.events.plugin` eklentilerini içerir.

Ayrıca, `RemoteServiceDiscovery.framework`, `com.apple.remoted.plugin`'den bilgi almayı sağlar ve `get_device`, `get_unique_device`, `connect` gibi işlevleri açığa çıkarır...

Bağlantı kullanıldığında ve hizmetin soket `fd`'si toplandığında, `remote_xpc_connection_*` sınıfı kullanılabilir.

Uzaktan hizmetler hakkında bilgi almak için `/usr/libexec/remotectl` cli aracını kullanarak şu parametreler ile bilgi almak mümkündür:
```bash
/usr/libexec/remotectl list # Get bridge devices
/usr/libexec/remotectl show ...# Get device properties and services
/usr/libexec/remotectl dumpstate # Like dump withuot indicateing a servie
/usr/libexec/remotectl [netcat|relay] ... # Expose a service in a port
...
```
BridgeOS ile ana bilgisayar arasındaki iletişim, özel bir IPv6 arayüzü üzerinden gerçekleşir. `MultiverseSupport.framework`, iletişim için kullanılacak `fd`'ye sahip soketlerin kurulmasına olanak tanır.\
Bu iletişimleri `netstat`, `nettop` veya açık kaynak seçeneği `netbottom` kullanarak bulmak mümkündür.

{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter**'da **bizi takip edin** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}
