# macOS XPC

<details>

<summary><strong>AWS hackleme becerilerini sıfırdan kahraman seviyesine öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong> ile!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek** paylaşın.

</details>

## Temel Bilgiler

XPC, macOS ve iOS üzerindeki işlemler arası iletişim anlamına gelen XNU (macOS tarafından kullanılan çekirdek) İşlem İletişimi'nin kısaltmasıdır. XPC, sistemdeki farklı işlemler arasında **güvenli, asenkron yöntem çağrıları yapma** mekanizması sağlar. Bu, Apple'ın güvenlik paradigmasının bir parçası olup, her **bileşenin** yalnızca işini yapmak için gereken **izinlere sahip olduğu** ayrıcalıklı uygulamaların oluşturulmasına olanak tanır ve bu şekilde bir sürecin tehlikeye girmesinden kaynaklanabilecek potansiyel zararı sınırlar.

XPC, aynı sistemde çalışan farklı programların veri alışverişi yapabilmesi için kullanılan bir İşlem İletişimi (IPC) yöntemi kullanır.

XPC'nin temel faydaları şunlardır:

1. **Güvenlik**: İşleri farklı süreçlere ayırarak, her sürece yalnızca ihtiyaç duyduğu izinler verilebilir. Bu, bir sürecin bile ele geçirilmiş olsa bile zarar verme yeteneğini sınırlar.
2. **Kararlılık**: XPC, çökmeleri oluştuğu bileşene izole eder. Bir süreç çöktüğünde, sistemdeki diğer bölümleri etkilemeden yeniden başlatılabilir.
3. **Performans**: XPC, farklı süreçlerde aynı anda farklı görevlerin çalıştırılmasına olanak tanır, bu nedenle kolay bir eşzamanlılık sağlar.

Tek **dezavantaj**, bir uygulamayı birkaç sürece ayırarak bunları XPC aracılığıyla iletişim kurmalarını sağlamaktır ve bu daha az verimli olabilir. Ancak günümüz sistemlerinde bunun neredeyse fark edilmez olduğu ve faydaların daha iyi olduğu söylenebilir.

## Uygulama Özel XPC Hizmetleri

Bir uygulamanın XPC bileşenleri, **uygulamanın kendisi içindedir**. Örneğin, Safari'de bunları **`/Applications/Safari.app/Contents/XPCServices`** dizininde bulabilirsiniz. Bunlar **`.xpc`** uzantısına sahiptir (örneğin **`com.apple.Safari.SandboxBroker.xpc`**) ve ana ikili dosyanın içinde de bir paket olarak bulunur: `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/MacOS/com.apple.Safari.SandboxBroker` ve bir `Info.plist: /Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/Info.plist`

Bir XPC bileşeninin diğer XPC bileşenlerinden veya ana uygulama ikili dosyasından farklı yetkilendirmelere ve ayrıcalıklara sahip olacağını düşünebilirsiniz. ANCAK, bir XPC hizmeti, **Info.plist** dosyasındaki [**JoinExistingSession**](https://developer.apple.com/documentation/bundleresources/information\_property\_list/xpcservice/joinexistingsession) ayarı "True" olarak yapılandırılmışsa, XPC hizmeti, onu çağıran uygulama ile **aynı güvenlik oturumunda** çalışır.

XPC hizmetleri, gerektiğinde **launchd** tarafından **başlatılır** ve tüm görevler tamamlandığında sistem kaynaklarını serbest bırakmak için **kapatılır**. **Uygulama özel XPC bileşenleri yalnızca uygulama tarafından kullanılabilir**, bu da potansiyel güvenlik açıklarına ilişkin riski azaltır.

## Sistem Genelindeki XPC Hizmetleri

Sistem genelindeki XPC hizmetleri tüm kullanıcılara erişilebilir. Bu hizmetler, launchd veya Mach türünde olabilir ve **`/System/Library/LaunchDaemons`**, **`/Library/LaunchDaemons`**, **`/System/Library/LaunchAgents`** veya **`/Library/LaunchAgents`** gibi belirli dizinlerde bulunan plist dosyalarında **tanımlanması** gerekmektedir.

Bu plist dosyalarında, hizmetin adını içeren **`MachServices`** adında bir anahtar ve ikili dosyanın yolunu içeren **`Program`** adında bir anahtar bulunur:
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
**`LaunchDameons`** içindekiler root tarafından çalıştırılır. Bu nedenle, bir yetkisiz işlem bunlardan biriyle iletişim kurabilirse, ayrıcalıkları yükseltebilir.

## XPC Olay Mesajları

Uygulamalar, farklı olay mesajlarına **abone olabilir** ve böyle olaylar gerçekleştiğinde **istenildiği zaman başlatılabilir**. Bu hizmetlerin kurulumu, **önceki dosyalarla aynı dizinlerde bulunan** ve ek bir **`LaunchEvent`** anahtarını içeren **l**aunchd plist dosyalarında yapılır.

### XPC Bağlantı Süreci Kontrolü

Bir işlem, bir XPC bağlantısı aracılığıyla bir yöntemi çağırmaya çalıştığında, **XPC hizmeti bu işlemin bağlanmasına izin verip vermediğini kontrol etmelidir**. İşte bunu kontrol etmek için yaygın kullanılan yöntemler ve yaygın hatalar:

{% content-ref url="macos-xpc-connecting-process-check/" %}
[macos-xpc-connecting-process-check](macos-xpc-connecting-process-check/)
{% endcontent-ref %}

## XPC Yetkilendirme

Apple, uygulamaların **bazı hakları yapılandırmasına ve nasıl elde edileceğine** izin verir, böylece çağrılan işlem bu haklara sahipse XPC hizmetinden bir yöntemi **çağırmasına izin verilir**:

{% content-ref url="macos-xpc-authorization.md" %}
[macos-xpc-authorization.md](macos-xpc-authorization.md)
{% endcontent-ref %}

## XPC Sniffer

XPC mesajlarını dinlemek için [**xpcspy**](https://github.com/hot3eed/xpcspy) kullanabilirsiniz, bu da **Frida** kullanır.
```bash
# Install
pip3 install xpcspy
pip3 install xpcspy --no-deps # To not make xpcspy install Frida 15 and downgrade your Frida installation

# Start sniffing
xpcspy -U -r -W <bundle-id>
## Using filters (i: for input, o: for output)
xpcspy -U <prog-name> -t 'i:com.apple.*' -t 'o:com.apple.*' -r
```
## XPC İletişimi C Kodu Örneği

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
{% tab title="xyz.hacktricks.service.plist" %}xyz.hacktricks.service.plist dosyası, macOS'ta XPC hizmetlerini başlatmak için kullanılan bir örnek bir property list dosyasıdır. Bu dosya, bir XPC hizmetinin nasıl başlatılacağını ve hangi işlevleri yerine getireceğini tanımlar.

Bu plist dosyasında, `Label` anahtarı, hizmetin benzersiz bir kimlik etiketi olarak kullanılacak bir dizedir. `MachServices` anahtarı, hizmetin hangi Mach servislerine erişebileceğini belirtir. `ProgramArguments` anahtarı, hizmetin çalıştırılacak uygulamanın yolu ve argümanlarını içerir.

Bu plist dosyasını kullanarak, bir XPC hizmetini başlatabilir ve hizmetin sağladığı işlevleri kullanabilirsiniz. Bu, macOS'ta inter-process iletişimi sağlamak ve hizmetler arasında veri paylaşımını kolaylaştırmak için yaygın olarak kullanılan bir yöntemdir.
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
{% tab title="oc_xpc_client.m" %}oc_xpc_client.m dosyası

```objective-c
#import <Foundation/Foundation.h>
#import <xpc/xpc.h>

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        xpc_connection_t connection = xpc_connection_create_mach_service("com.apple.securityd", NULL, XPC_CONNECTION_MACH_SERVICE_PRIVILEGED);
        xpc_connection_set_event_handler(connection, ^(xpc_object_t event) {
            xpc_type_t type = xpc_get_type(event);
            if (type == XPC_TYPE_DICTIONARY) {
                const char *description = xpc_dictionary_get_string(event, "description");
                if (description) {
                    printf("Received event: %s\n", description);
                }
            }
        });
        xpc_connection_resume(connection);
        dispatch_main();
    }
    return 0;
}
```

Bu örnek, Objective-C kullanarak macOS'ta XPC (Inter-Process Communication) istemcisi oluşturmayı göstermektedir. XPC, farklı süreçler arasında iletişim kurmak için kullanılan bir mekanizmadır. Bu örnekte, "com.apple.securityd" adlı bir Mach servisine bağlanan bir XPC bağlantısı oluşturulur. Bağlantıya bir olay işleyici atanır ve olaylar alındığında ekrana yazdırılır.

Bu örneği derlemek ve çalıştırmak için aşağıdaki adımları izleyebilirsiniz:

1. Bir Objective-C projesi oluşturun ve `oc_xpc_client.m` dosyasını projenize ekleyin.
2. Projenizi derleyin ve çalıştırın.

Bu örnek, XPC istemcisi oluşturmanın temel bir örneğini sunmaktadır. Daha fazla özellik eklemek veya farklı bir XPC servisiyle iletişim kurmak için kodu özelleştirebilirsiniz.
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
{% tab title="xyz.hacktricks.svcoc.plist" %}

Bu dosya, macOS'ta XPC hizmetlerini başlatmak için kullanılan bir örnek bir önyükleme ajanıdır. XPC, farklı süreçler arasında iletişim kurmak için kullanılan bir IPC (Inter-Process Communication) mekanizmasıdır. Bu plist dosyası, bir XPC hizmetini başlatmak için gerekli olan yapılandırmayı içerir.

Bu dosyayı kullanarak, bir XPC hizmetini başlatmak için gerekli olan parametreleri belirleyebilirsiniz. Örneğin, hedeflenen hizmetin kimlik bilgilerini, çalıştırılacak komutları ve diğer yapılandırma ayarlarını belirleyebilirsiniz.

Bu plist dosyasını kullanarak, hedeflenen bir XPC hizmetini kötüye kullanabilir ve ayrıcalık yükseltme saldırıları gerçekleştirebilirsiniz. Ancak, bu tür saldırılar yasa dışıdır ve yalnızca yasal izinlerle gerçekleştirilmelidir.

Bu dosyanın kullanımıyla ilgili daha fazla bilgi için, macOS XPC hizmetlerini kötüye kullanma konusundaki ilgili bölüme bakabilirsiniz.

{% endtab %}
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

Bu bölümde, Dylb kodu içindeki istemci hakkında bilgi verilecektir.

Dylb, macOS'ta kullanılan bir IPC (İşlem Arası İletişim) mekanizmasıdır. Bu mekanizma, farklı süreçler arasında iletişim kurmak için kullanılır. Dylb kodu, bir istemci ve bir sunucu olmak üzere iki bileşenden oluşur.

İstemci, Dylb sunucusuna bağlanarak talepler gönderir ve yanıtları alır. İstemci, sunucuyla iletişim kurmak için belirli bir protokolü takip eder. Bu protokol, istemcinin sunucuya hangi talepleri gönderebileceğini ve nasıl yanıtlar alabileceğini belirler.

Dylb kodu içindeki istemci, genellikle bir uygulama tarafından kullanılır. Uygulama, Dylb istemcisini kullanarak başka bir süreçle iletişim kurabilir ve veri alışverişi yapabilir. Bu, uygulamanın farklı süreçler arasında bilgi paylaşmasını sağlar.

Dylb kodu içindeki istemci, güvenlik açıklarına neden olabilecek potansiyel bir noktadır. İstismarcılar, istemci tarafında hatalar bulup bunları kullanarak ayrıcalık yükseltme saldırıları gerçekleştirebilirler. Bu nedenle, Dylb kodu içindeki istemciyi güvenli bir şekilde uygulamak önemlidir.

Bu bölümde, Dylb kodu içindeki istemci hakkında daha fazla bilgi ve güvenlik önlemleri bulabilirsiniz.
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
<details>

<summary><strong>AWS hackleme becerilerini sıfırdan kahraman seviyesine öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek isterseniz** veya **HackTricks'i PDF olarak indirmek isterseniz** [**ABONELİK PLANLARINA**](https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'ı takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>
